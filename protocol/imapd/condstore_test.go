package imapd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestCondstoreChangedSince proves the change-log-as-MODSEQ payoff: an IMAP
// client can do incremental sync via CONDSTORE CHANGEDSINCE, which the kernel
// serves as a changelog replay (messages with modseq > n). Deliver two
// messages; capture the head modseq after the first; CHANGEDSINCE that value
// must return only the second.
func TestCondstoreChangedSince(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Deliver message 1, capture head modseq, then deliver message 2.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: one\r\n\r\nfirst\r\n")); err != nil {
		t.Fatal(err)
	}
	var afterFirst int64
	mustScan(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &afterFirst, accID)
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: two\r\n\r\nsecond\r\n")); err != nil {
		t.Fatal(err)
	}

	// IMAP client.
	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
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

	// CHANGEDSINCE afterFirst — must return ONLY message 2 (uid 2), with MODSEQ.
	if err := ic.WriteCommandf("", "uid fetch 1:* (FLAGS) (CHANGEDSINCE %d)", afterFirst); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	var uids []uint32
	sawModseq := false
	for _, u := range resp.Untagged {
		f, ok := u.(imapclient.UntaggedFetch)
		if !ok {
			continue
		}
		for _, a := range f.Attrs {
			switch a.(type) {
			case imapclient.FetchUID:
				uids = append(uids, uint32(a.(imapclient.FetchUID)))
			case imapclient.FetchModSeq:
				sawModseq = true
			}
		}
	}
	if len(uids) != 1 || uids[0] != 2 {
		t.Fatalf("CHANGEDSINCE %d returned uids %v, want [2]", afterFirst, uids)
	}
	if !sawModseq {
		t.Fatalf("CONDSTORE FETCH should include MODSEQ")
	}
	t.Logf("OK: CHANGEDSINCE %d returned only uid 2 (changelog replay); MODSEQ present", afterFirst)
}

var _ = strings.Contains
