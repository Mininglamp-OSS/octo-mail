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
)

// TestUIDOnly proves IMAP UIDONLY (RFC 9586): after ENABLE UIDONLY, UID FETCH
// returns "* UIDFETCH <uid> (...)" responses, and a message-sequence-number
// command (plain FETCH) is rejected with [UIDREQUIRED]. Driven by the imapclient.
func TestUIDOnly(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: u\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	// Driven raw over TCP: the UIDONLY response is the spec-correct
	// "* UIDFETCH <uid> (...)" (RFC 9586), which the mox imapclient parser does
	// not model (it expects a leading message number), so we read plain lines.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &imapd.Server{Dir: dir}
	go func() {
		for {
			nc, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { _ = srv.Serve(ctx, nc) }()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	rc := newRawIMAP(t, conn)

	rc.mustOK("a1", "login u1@example.com x")
	rc.mustOK("a2", "enable uidonly")
	rc.mustOK("a3", "select INBOX")

	// UID FETCH → "* UIDFETCH <uid>" response (and no legacy "* n FETCH").
	un := rc.mustOK("a4", "uid fetch 1 (FLAGS)")
	sawUIDFetch := false
	for _, l := range un {
		if strings.HasPrefix(l, "* UIDFETCH 1 ") {
			sawUIDFetch = true
		}
		if len(l) > 2 && l[2] >= '0' && l[2] <= '9' && strings.Contains(l, " FETCH ") {
			t.Fatalf("UIDONLY session must not emit legacy * n FETCH: %q", l)
		}
	}
	if !sawUIDFetch {
		t.Fatalf("UID FETCH under UIDONLY did not produce * UIDFETCH: %v", un)
	}

	// A message-sequence-number FETCH is rejected with [UIDREQUIRED].
	_, tagged := rc.cmd("a5", "fetch 1 (FLAGS)")
	if !strings.Contains(strings.ToUpper(tagged), "UIDREQUIRED") {
		t.Fatalf("expected [UIDREQUIRED], got %q", tagged)
	}

	t.Logf("OK: ENABLE UIDONLY → UID FETCH yields * UIDFETCH; seq-number FETCH rejected with [UIDREQUIRED]")
}
