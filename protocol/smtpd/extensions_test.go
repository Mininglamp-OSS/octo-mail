package smtpd_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestSMTPExtensions proves P1-5: EHLO advertises 8BITMIME/DSN/CHUNKING; MAIL
// FROM accepts DSN params (RET/ENVID); and a BDAT-chunked message (RFC 3030
// CHUNKING) is accepted and delivered. Driven with raw SMTP (the smtpclient does
// not do BDAT).
func TestSMTPExtensions(t *testing.T) {
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
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com"}
	cc, sconn := net.Pipe()
	go func() { _ = mx.Serve(ctx, sconn) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // 220

	// EHLO advertises the new extensions.
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
	for _, ext := range []string{"8BITMIME", "DSN", "CHUNKING"} {
		if !strings.Contains(joined, ext) {
			t.Fatalf("EHLO missing %s:\n%s", ext, joined)
		}
	}

	// MAIL FROM with DSN params (RET/ENVID) — accepted (250).
	cc.Write([]byte("MAIL FROM:<a@remote.example> RET=HDRS ENVID=abc123\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL with DSN params: %q, want 250", r)
	}
	cc.Write([]byte("RCPT TO:<u1@example.com> NOTIFY=SUCCESS,FAILURE\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT with NOTIFY: %q, want 250", r)
	}

	// BDAT chunking: send the message in two chunks, last marked LAST.
	body := "From: a@remote.example\r\nTo: u1@example.com\r\nSubject: chunked\r\n\r\nhello via BDAT\r\n"
	half := len(body) / 2
	c1 := body[:half]
	c2 := body[half:]
	fmt.Fprintf(cc, "BDAT %d\r\n", len(c1))
	cc.Write([]byte(c1))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("BDAT chunk 1: %q, want 250", r)
	}
	fmt.Fprintf(cc, "BDAT %d LAST\r\n", len(c2))
	cc.Write([]byte(c2))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("BDAT LAST: %q, want 250", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	// The chunked message was delivered.
	var inbox int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, accID).Scan(&inbox)
		if inbox == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if inbox != 1 {
		t.Fatalf("BDAT-chunked message not delivered: inbox=%d", inbox)
	}

	t.Logf("OK: EHLO 8BITMIME/DSN/CHUNKING; MAIL RET/ENVID + RCPT NOTIFY accepted; BDAT 2-chunk message delivered")
}
