package imapd_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestQResyncVanished proves QRESYNC (RFC 7162): (1) live EXPUNGE after ENABLE
// QRESYNC is reported as a single VANISHED (with UIDs) instead of per-message
// EXPUNGE; (2) a reconnecting client that passes SELECT ... (QRESYNC (uidvalidity
// modseq)) receives VANISHED (EARLIER) for UIDs expunged since its modseq — the
// change-log is the durable expunge history. Driven by the unmodified
// imapclient over a real TCP socket.
func TestQResyncVanished(t *testing.T) {
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

	// Deliver three messages (uids 1,2,3).
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"one", "two", "three"} {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: "+sub+"\r\n\r\n"+sub+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	// Snapshot the modseq a client would have "seen" after the initial sync.
	var baseModseq int64
	mustScan(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &baseModseq, accID)
	// Read UIDVALIDITY for the QRESYNC reconnect.
	var uidValidity int64
	mustScan(t, s, ctx, `SELECT uidvalidity FROM mailboxes WHERE account_id=$1 AND name='Inbox'`, &uidValidity, accID)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &imapd.Server{Dir: dir}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.Serve(ctx, nc) }()
		}
	}()

	dial := func() *imapclient.Conn {
		cc, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
		ic, err := imapclient.New(cc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ic.Login("u1@example.com", "x"); err != nil {
			t.Fatal(err)
		}
		return ic
	}

	// --- Part 1: live EXPUNGE → VANISHED after ENABLE QRESYNC. ---
	ic := dial()
	if err := ic.WriteCommandf("", "enable qresync"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}
	// Mark uid 2 \Deleted, then EXPUNGE — expect a VANISHED response with UID 2.
	if err := ic.WriteCommandf("", "uid store 2 +FLAGS (\\Deleted)"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	if err := ic.WriteCommandf("", "expunge"); err != nil {
		t.Fatal(err)
	}
	exResp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	sawVanished := false
	sawExpunge := false
	for _, u := range exResp.Untagged {
		switch v := u.(type) {
		case imapclient.UntaggedVanished:
			sawVanished = true
			if v.Earlier {
				t.Fatalf("live EXPUNGE VANISHED should not be EARLIER")
			}
			if !numSetHas(v.UIDs, 2) {
				t.Fatalf("VANISHED UIDs = %v, want to contain 2", v.UIDs)
			}
		case imapclient.UntaggedExpunge:
			sawExpunge = true
		}
	}
	if !sawVanished {
		t.Fatalf("EXPUNGE after ENABLE QRESYNC did not produce VANISHED: %+v", exResp.Untagged)
	}
	if sawExpunge {
		t.Fatalf("QRESYNC session should not emit legacy * n EXPUNGE")
	}
	ic.Close()

	// --- Part 2: reconnect with QRESYNC → VANISHED (EARLIER) for uid 2. ---
	ic2 := dial()
	defer ic2.Close()
	if err := ic2.WriteCommandf("", "enable qresync"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic2.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	// SELECT INBOX (QRESYNC (<uidvalidity> <baseModseq>)) — baseModseq predates the
	// expunge of uid 2, so the server must report it as VANISHED (EARLIER).
	if err := ic2.WriteCommandf("", "select INBOX (QRESYNC (%d %d))", uidValidity, baseModseq); err != nil {
		t.Fatal(err)
	}
	selResp, err := ic2.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	sawEarlier := false
	for _, u := range selResp.Untagged {
		if v, ok := u.(imapclient.UntaggedVanished); ok && v.Earlier {
			sawEarlier = true
			if !numSetHas(v.UIDs, 2) {
				t.Fatalf("VANISHED (EARLIER) UIDs = %v, want to contain 2", v.UIDs)
			}
		}
	}
	if !sawEarlier {
		t.Fatalf("QRESYNC SELECT did not report VANISHED (EARLIER) for expunged uid 2: %+v", selResp.Untagged)
	}

	t.Logf("OK: QRESYNC — live EXPUNGE→VANISHED(UID 2); reconnect SELECT (QRESYNC ...)→VANISHED (EARLIER) UID 2 from the change-log")
}

// numSetHas reports whether a NumSet contains n (handles single numbers and ranges).
func numSetHas(ns imapclient.NumSet, n uint32) bool {
	for _, r := range ns.Ranges {
		lo := r.First
		hi := lo
		if r.Last != nil {
			hi = *r.Last
		}
		if n >= lo && n <= hi {
			return true
		}
	}
	return false
}
