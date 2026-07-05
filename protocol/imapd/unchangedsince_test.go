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

// TestStoreUnchangedSince proves P1-1 CONDSTORE optimistic-lock: a STORE with
// (UNCHANGEDSINCE n) only applies to messages whose modseq <= n. When a message
// has been modified since n, it is reported in the [MODIFIED ...] response code
// and the flag is NOT applied — the classic lost-update guard. A fresh
// UNCHANGEDSINCE at the current modseq succeeds.
func TestStoreUnchangedSince(t *testing.T) {
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

	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: one\r\n\r\nfirst\r\n")); err != nil {
		t.Fatal(err)
	}
	// Capture the modseq snapshot the client "saw" (stale after we modify below).
	var staleModseq int64
	mustScan(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &staleModseq, accID)

	// A concurrent modification bumps the message's modseq past staleModseq.
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: two\r\n\r\nsecond\r\n")); err != nil {
		t.Fatal(err)
	}
	// Flag message 1 out-of-band so its modseq exceeds staleModseq.
	srv := &imapd.Server{Dir: dir}
	cc, scpipe := net.Pipe()
	go func() { _ = srv.Serve(ctx, scpipe) }()
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
	// Bump uid 1's modseq (this is the "someone else changed it" step).
	if err := ic.WriteCommandf("", "uid store 1 +FLAGS (\\Answered)"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatal(err)
	}

	// Now attempt a conditional STORE with the STALE modseq: uid 1 has changed,
	// so it must be rejected (reported MODIFIED) and \Flagged NOT applied.
	if err := ic.WriteCommandf("", "uid store 1 (UNCHANGEDSINCE %d) +FLAGS (\\Flagged)", staleModseq); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	respText := strings.ToUpper(resp.Result.Text)
	_, isModified := resp.Result.Code.(imapclient.CodeModified)
	if !isModified && !strings.Contains(respText, "MODIFIED") {
		t.Fatalf("conditional STORE response = %q code=%#v, want a [MODIFIED ...] code", resp.Result.Text, resp.Result.Code)
	}
	// The \Flagged flag must NOT have been applied to uid 1.
	var flagged bool
	mustScan(t, s, ctx, `SELECT f_flagged FROM messages WHERE account_id=$1 AND mailbox_id=(SELECT id FROM mailboxes WHERE account_id=$1 AND name='Inbox') AND uid=1`, &flagged, accID)
	if flagged {
		t.Fatalf("uid 1 was flagged despite failing UNCHANGEDSINCE guard")
	}

	// A conditional STORE at the CURRENT head modseq succeeds and applies.
	var head int64
	mustScan(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head, accID)
	if err := ic.WriteCommandf("", "uid store 1 (UNCHANGEDSINCE %d) +FLAGS (\\Flagged)", head); err != nil {
		t.Fatal(err)
	}
	resp2, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if _, isMod := resp2.Result.Code.(imapclient.CodeModified); isMod || strings.Contains(strings.ToUpper(resp2.Result.Text), "MODIFIED") {
		t.Fatalf("STORE at head modseq should succeed, got MODIFIED: %q", resp2.Result.Text)
	}
	mustScan(t, s, ctx, `SELECT f_flagged FROM messages WHERE account_id=$1 AND mailbox_id=(SELECT id FROM mailboxes WHERE account_id=$1 AND name='Inbox') AND uid=1`, &flagged, accID)
	if !flagged {
		t.Fatalf("uid 1 not flagged after a satisfied UNCHANGEDSINCE store")
	}

	t.Logf("OK: UNCHANGEDSINCE rejected the stale-modseq STORE ([MODIFIED], flag not applied); the at-head STORE applied")
}
