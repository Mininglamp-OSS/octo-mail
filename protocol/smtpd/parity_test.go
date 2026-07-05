package smtpd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestSMTPParityExtensions drives the mox-parity SMTP additions:
// ENHANCEDSTATUSCODES + LIMITS RCPTMAX advertising (RFC 2034 / 9422), RCPTMAX
// enforcement (452 past the cap), and the VRFY/EXPN/HELP verbs. Driven raw.
func TestSMTPParityExtensions(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	// MX with a small recipient cap so RCPTMAX enforcement is easy to hit.
	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", MaxRcpt: 2}
	cc, sc := net.Pipe()
	go func() { _ = mx.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // 220 greeting

	// EHLO advertises ENHANCEDSTATUSCODES + LIMITS RCPTMAX.
	cc.Write([]byte("EHLO client.example\r\n"))
	var ehlo []string
	for {
		l := br.line()
		ehlo = append(ehlo, l)
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	joined := strings.Join(ehlo, "\n")
	if !strings.Contains(joined, "ENHANCEDSTATUSCODES") {
		t.Fatalf("EHLO missing ENHANCEDSTATUSCODES:\n%s", joined)
	}
	if !strings.Contains(joined, "LIMITS RCPTMAX=2") {
		t.Fatalf("EHLO missing LIMITS RCPTMAX=2:\n%s", joined)
	}

	// VRFY → 252, EXPN → 502, HELP → 214.
	cc.Write([]byte("VRFY u1@example.com\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "252") {
		t.Fatalf("VRFY got %q, want 252", r)
	}
	cc.Write([]byte("EXPN list\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "502") {
		t.Fatalf("EXPN got %q, want 502", r)
	}
	cc.Write([]byte("HELP\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "214") {
		t.Fatalf("HELP got %q, want 214", r)
	}

	// RCPTMAX enforcement: 2 recipients accepted, the 3rd rejected with 452.
	cc.Write([]byte("MAIL FROM:<a@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL got %q", r)
	}
	for i := 1; i <= 2; i++ {
		cc.Write([]byte("RCPT TO:<u1@example.com>\r\n"))
		if r := br.line(); !strings.HasPrefix(r, "250") {
			t.Fatalf("RCPT %d got %q, want 250", i, r)
		}
	}
	cc.Write([]byte("RCPT TO:<u1@example.com>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "452") {
		t.Fatalf("RCPT past RCPTMAX got %q, want 452", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	t.Logf("OK: EHLO advertises ENHANCEDSTATUSCODES + LIMITS RCPTMAX=2; RCPTMAX enforced (452); VRFY 252 / EXPN 502 / HELP 214")
}
