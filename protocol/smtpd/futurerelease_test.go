package smtpd_test

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestFutureRelease drives FUTURERELEASE (RFC 4865): EHLO advertises it; a
// submission with MAIL FROM HOLDFOR=<sec> enqueues the outbound message with a
// future next_attempt (not due now), so the queue worker won't deliver it until
// the hold elapses; an out-of-range HOLDFOR is rejected. Driven raw.
func TestFutureRelease(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, dom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &dom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, dom, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	sub := &smtpd.Server{Dir: dir, Hostname: "mail.sender.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // greeting

	// EHLO advertises FUTURERELEASE.
	cc.Write([]byte("EHLO client.example\r\n"))
	var ehlo []string
	for {
		l := br.line()
		ehlo = append(ehlo, l)
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	if !strings.Contains(strings.Join(ehlo, "\n"), "FUTURERELEASE") {
		t.Fatalf("EHLO missing FUTURERELEASE:\n%s", strings.Join(ehlo, "\n"))
	}

	tok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + tok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q", r)
	}

	// Out-of-range HOLDFOR is rejected.
	cc.Write([]byte("MAIL FROM:<me@sender.example> HOLDFOR=999999999\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "501") {
		t.Fatalf("out-of-range HOLDFOR got %q, want 501", r)
	}
	cc.Write([]byte("RSET\r\n"))
	_ = br.line()

	// Valid HOLDFOR=3600: message enqueued with a ~1h-future next_attempt.
	cc.Write([]byte("MAIL FROM:<me@sender.example> HOLDFOR=3600\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL HOLDFOR got %q, want 250", r)
	}
	cc.Write([]byte("RCPT TO:<you@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT got %q", r)
	}
	cc.Write([]byte("DATA\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA got %q", r)
	}
	cc.Write([]byte("From: me@sender.example\r\nTo: you@remote.example\r\nSubject: held\r\n\r\nlater\r\n.\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("end-of-data got %q", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	// The queued row's next_attempt is ~1h in the future (not due now).
	var notDue bool
	var secs float64
	if err := s.Pool.QueryRow(ctx,
		`SELECT next_attempt > now() + interval '50 minutes', EXTRACT(EPOCH FROM (next_attempt - now())) FROM queue LIMIT 1`).Scan(&notDue, &secs); err != nil {
		t.Fatalf("query queue: %v", err)
	}
	if !notDue {
		t.Fatalf("FUTURERELEASE HOLDFOR=3600 did not defer next_attempt (delta=%.0fs, want ~3600)", secs)
	}

	t.Logf("OK: EHLO advertises FUTURERELEASE; HOLDFOR=3600 deferred delivery ~%.0fs; out-of-range HOLDFOR rejected (501)", secs)
}
