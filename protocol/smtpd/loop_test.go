package smtpd_test

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/smtpclient"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestSMTPReceiveThenIMAPFetch is the full P1-A loop: a real SMTP client
// (the smtpclient, unmodified) delivers a message to our smtpd, which appends it
// to the change-log kernel; then a real IMAP client (the imapclient, unmodified)
// fetches it back through imapd. Two reused protocol clients, two kernel-bound
// servers, one change-log — end to end over in-memory pipes.
func TestSMTPReceiveThenIMAPFetch(t *testing.T) {
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
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	exec(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	exec(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)

	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// --- Deliver via real SMTP ---
	smtpSrv := &smtpd.Server{Dir: dir, Hostname: "octo-mail.test"}
	cConn, sConn := net.Pipe()
	go func() { _ = smtpSrv.Serve(ctx, sConn) }()
	_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))

	cl, err := smtpclient.New(ctx, slog.Default(), cConn,
		smtpclient.TLSSkip, false,
		dns.Domain{ASCII: "sender.test"}, dns.Domain{ASCII: "octo-mail.test"},
		smtpclient.Opts{})
	if err != nil {
		t.Fatalf("smtpclient new: %v", err)
	}
	const msg = "From: alice@remote.example\r\nTo: u1@example.com\r\nSubject: via smtp\r\n\r\nsmtp body here\r\n"
	err = cl.Deliver(ctx, "alice@remote.example", "u1@example.com", int64(len(msg)), strings.NewReader(msg), false, false, false)
	if err != nil {
		t.Fatalf("smtp deliver: %v", err)
	}
	_ = cl.Close()

	// --- Fetch via real IMAP ---
	imapSrv := &imapd.Server{Dir: dir}
	iC, iS := net.Pipe()
	go func() { _ = imapSrv.Serve(ctx, iS) }()
	_ = iC.SetDeadline(time.Now().Add(10 * time.Second))

	ic, err := imapclient.New(iC, nil)
	if err != nil {
		t.Fatalf("imapclient new: %v", err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatalf("IMAP login: %v", err)
	}
	sel, err := ic.Select("INBOX")
	if err != nil {
		t.Fatalf("IMAP select: %v", err)
	}
	if !hasExists(sel, 1) {
		t.Fatalf("expected 1 EXISTS after SMTP delivery; got %+v", sel.Untagged)
	}
	if err := ic.WriteCommandf("", "uid fetch 1 (BODY[])"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	body := fetchBody(resp)
	if !strings.Contains(body, "smtp body here") {
		t.Fatalf("IMAP FETCH did not return SMTP-delivered body; got %q", body)
	}
	t.Logf("OK: message delivered via real SMTP, fetched via real IMAP, through one change-log")
}

func hasExists(r imapclient.Response, n uint32) bool {
	for _, u := range r.Untagged {
		if e, ok := u.(imapclient.UntaggedExists); ok && uint32(e) == n {
			return true
		}
	}
	return false
}

func fetchBody(r imapclient.Response) string {
	for _, u := range r.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if b, ok := a.(imapclient.FetchBody); ok {
					return b.Body
				}
			}
		}
	}
	return ""
}

func scan(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("scan %q: %v", sql, err)
	}
}
func exec(t *testing.T, s *postgres.Store, ctx context.Context, sql string, args ...any) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
