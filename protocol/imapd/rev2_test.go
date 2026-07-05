package imapd_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestIMAP4rev2AndUTF8 drives IMAP4rev2 (RFC 9051) and UTF8=ACCEPT (RFC 6855):
// CAPABILITY advertises both; ENABLE echoes exactly the recognized caps; a
// rev2-enabled SELECT omits the "* 0 RECENT" line (RECENT was removed in rev2);
// and APPEND accepts the UTF8 (<literal>) wrapper. Driven raw so the exact
// SELECT response lines and the ENABLED echo are asserted directly.
func TestIMAP4rev2AndUTF8(t *testing.T) {
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
	// Seed a message so INBOX exists.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: seed\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, cc)

	// CAPABILITY advertises both new caps.
	capUn := rc.mustOK("a1", "capability")
	caps := strings.Join(capUn, " ")
	for _, want := range []string{"IMAP4rev2", "UTF8=ACCEPT"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("CAPABILITY missing %s: %s", want, caps)
		}
	}

	rc.mustOK("a2", "login u1@example.com x")

	// ENABLE echoes exactly the recognized caps (not the raw argument).
	un := rc.mustOK("a3", "enable IMAP4rev2 UTF8=ACCEPT BOGUSCAP")
	enabled := firstWithPrefix(t, un, "* ENABLED")
	if !strings.Contains(enabled, "IMAP4rev2") || !strings.Contains(enabled, "UTF8=ACCEPT") {
		t.Fatalf("ENABLED missing recognized caps: %q", enabled)
	}
	if strings.Contains(enabled, "BOGUSCAP") {
		t.Fatalf("ENABLED echoed an unrecognized cap: %q", enabled)
	}

	// A rev2-enabled SELECT must NOT emit "* 0 RECENT" (RECENT removed in rev2).
	un = rc.mustOK("a4", "select INBOX")
	for _, l := range un {
		if strings.HasSuffix(l, "RECENT") {
			t.Fatalf("rev2 SELECT emitted RECENT: %q", l)
		}
	}
	// Sanity: EXISTS is still present.
	if firstContaining(t, un, "EXISTS") == "" {
		t.Fatalf("SELECT missing EXISTS: %v", un)
	}

	// APPEND with the UTF8 (<literal>) wrapper (RFC 6855). Non-sync literal keeps
	// it a single write; a UTF-8 subject exercises the 8-bit-accept path.
	msg := "Subject: café\r\n\r\nutf8 body\r\n"
	appendCmd := fmt.Sprintf("a5 APPEND INBOX UTF8 ({%d+}\r\n%s)\r\n", len(msg), msg)
	if _, err := cc.Write([]byte(appendCmd)); err != nil {
		t.Fatal(err)
	}
	tagged := readToTagLine(t, rc, "a5")
	if !strings.Contains(tagged, " OK") {
		t.Fatalf("APPEND UTF8 -> %q, want OK", tagged)
	}

	// The appended message is retrievable (now 2 messages).
	un = rc.mustOK("a6", "status INBOX (MESSAGES)")
	st := firstWithPrefix(t, un, "* STATUS")
	if !strings.Contains(st, "MESSAGES 2") {
		t.Fatalf("after UTF8 APPEND, STATUS = %q, want MESSAGES 2", st)
	}

	t.Logf("OK: CAPABILITY has IMAP4rev2+UTF8=ACCEPT; ENABLE echoes only recognized caps; rev2 SELECT omits RECENT; APPEND UTF8 (literal) accepted")
}

// readToTagLine reads until the tagged completion line and returns it.
func readToTagLine(t *testing.T, rc *rawIMAP, tag string) string {
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read tag %s: %v", tag, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return line
		}
	}
}
