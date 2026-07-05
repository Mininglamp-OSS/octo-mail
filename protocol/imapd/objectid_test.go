package imapd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestObjectID drives OBJECTID (RFC 8474): the MAILBOXID response code in SELECT,
// the MAILBOXID STATUS attribute, and the EMAILID/THREADID FETCH items. Driven
// raw because imapclient does not model these responses. Change-log ids back the
// object ids, so the same identity is stable across SELECT/STATUS/FETCH.
func TestObjectID(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, thread_refs, projection_cursor RESTART IDENTITY CASCADE`); err != nil {
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

	// Two messages in a reply thread so THREADID is shared after projection.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(raw string) {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	deliver("From: a@remote.example\r\nSubject: root\r\nMessage-ID: <r@x>\r\n\r\nroot\r\n")
	deliver("From: b@remote.example\r\nSubject: Re: root\r\nMessage-ID: <p@x>\r\nIn-Reply-To: <r@x>\r\nReferences: <r@x>\r\n\r\nreply\r\n")

	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("thread drain: %v", err)
	}

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

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, conn)
	rc.mustOK("a1", "login u1@example.com x")

	// SELECT emits an untagged "* OK [MAILBOXID (B<id>)]" response code.
	un := rc.mustOK("a2", "select INBOX")
	mboxID := ""
	for _, l := range un {
		if i := strings.Index(l, "[MAILBOXID ("); i >= 0 {
			rest := l[i+len("[MAILBOXID ("):]
			if j := strings.IndexByte(rest, ')'); j >= 0 {
				mboxID = rest[:j]
			}
		}
	}
	if mboxID == "" || !strings.HasPrefix(mboxID, "B") {
		t.Fatalf("SELECT missing MAILBOXID (B<id>): %v", un)
	}

	// STATUS MAILBOXID reports the same id for the same mailbox.
	un = rc.mustOK("a3", "status INBOX (MAILBOXID)")
	statusLine := firstWithPrefix(t, un, "* STATUS")
	if !strings.Contains(statusLine, "MAILBOXID ("+mboxID+")") {
		t.Fatalf("STATUS MAILBOXID = %q, want same id %q as SELECT", statusLine, mboxID)
	}

	// FETCH EMAILID/THREADID: both messages carry a stable EMAILID and, after the
	// thread projection, a shared THREADID.
	un = rc.mustOK("a4", "uid fetch 1:2 (EMAILID THREADID)")
	var emailIDs, threadIDs []string
	for _, l := range un {
		if !strings.HasPrefix(l, "* ") || !strings.Contains(l, "FETCH") {
			continue
		}
		if id := extractParen(l, "EMAILID"); id != "" {
			emailIDs = append(emailIDs, id)
		}
		if id := extractParen(l, "THREADID"); id != "" {
			threadIDs = append(threadIDs, id)
		}
	}
	if len(emailIDs) != 2 {
		t.Fatalf("expected 2 EMAILIDs, got %v (untagged=%v)", emailIDs, un)
	}
	for _, e := range emailIDs {
		if !strings.HasPrefix(e, "M") {
			t.Fatalf("EMAILID %q missing M prefix", e)
		}
	}
	if emailIDs[0] == emailIDs[1] {
		t.Fatalf("two distinct messages share an EMAILID: %v", emailIDs)
	}
	if len(threadIDs) != 2 {
		t.Fatalf("expected 2 THREADIDs, got %v", threadIDs)
	}
	if threadIDs[0] != threadIDs[1] {
		t.Fatalf("threaded reply chain has differing THREADIDs %v, want shared", threadIDs)
	}
	if !strings.HasPrefix(threadIDs[0], "T") {
		t.Fatalf("THREADID %q missing T prefix", threadIDs[0])
	}

	t.Logf("OK: MAILBOXID %s consistent SELECT/STATUS; EMAILID distinct per message %v; THREADID shared across reply chain %v", mboxID, emailIDs, threadIDs)
}

// extractParen returns the value inside "KEY (value)" within a FETCH line, or "".
func extractParen(line, key string) string {
	i := strings.Index(line, key+" (")
	if i < 0 {
		return ""
	}
	rest := line[i+len(key)+2:]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
