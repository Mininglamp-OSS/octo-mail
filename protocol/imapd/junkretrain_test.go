package imapd_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestJunkRetrainOnFlag proves R2-5: flagging a message \Junk via IMAP STORE
// trains the account's bayesian filter as spam (and removing \Junk trains ham),
// so the filter learns from user corrections. Verified by classifying a similar
// message before and after the correction.
func TestJunkRetrainOnFlag(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	mgr := junkfilter.NewManager(t.TempDir(), junkfilter.DefaultParams, 0.95)
	defer mgr.Close()
	// Pre-train enough ham so the filter is significant, plus some spam baseline.
	for i := 0; i < 60; i++ {
		mgr.Train(ctx, accID, true, []byte(fmt.Sprintf("Subject: work\r\n\r\nmeeting notes and project plan item %d\r\n", i)))
		mgr.Train(ctx, accID, false, []byte(fmt.Sprintf("Subject: promo\r\n\r\ncheap discount sale offer number %d\r\n", i)))
	}

	// Deliver several novel spam-like messages sharing distinctive tokens.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		spammy := fmt.Sprintf("Subject: zorble\r\n\r\nzorble wibble wobble flimflam grobble %d\r\n", i)
		if _, err := target.Deliver(ctx, &store.Message{}, memReader(spammy)); err != nil {
			t.Fatal(err)
		}
	}

	// Baseline classification of a similar "zorble" message: not junk yet.
	probe := []byte("Subject: zorble\r\n\r\nzorble wibble flimflam grobble special\r\n")
	_, _, isJunkBefore, _ := mgr.Classify(ctx, accID, probe)
	if isJunkBefore {
		t.Fatalf("probe classified as junk before any \\Junk training")
	}

	// Mark each delivered message \Junk once via IMAP STORE → trains spam once each.
	srv := &imapd.Server{Dir: dir, Junk: mgr}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}
	// One \Junk mark per message (a genuine user correction), UIDs 1..15.
	if err := ic.WriteCommandf("", "uid store 1:15 +FLAGS (\\Junk)"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatal(err)
	}

	// After training the "zorble" tokens as spam, the probe should now be junk.
	prob, sig, isJunkAfter, _ := mgr.Classify(ctx, accID, probe)
	if !sig {
		t.Fatalf("classification not significant after retrain")
	}
	if !isJunkAfter {
		t.Fatalf("probe not junk after \\Junk retraining (prob=%.3f) — retrain hook not effective", prob)
	}
	t.Logf("OK: STORE +FLAGS \\Junk retrained spam; similar message now classified junk (prob=%.3f)", prob)
}
