package smtpd_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

// TestSubmissionSCRAM proves SMTP submission AUTH SCRAM-SHA-256 (RFC 4954 SASL
// over SMTP + RFC 5802): the mox smtpclient runs the SCRAM exchange over 334
// continuations — the password never crosses the wire — and enqueues an outbound
// message. Wrong password is rejected.
func TestSubmissionSCRAM(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, senderID, sdom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &senderID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &sdom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	subSrv := &smtpd.Server{
		Dir:        dir,
		Hostname:   "mail.sender.example",
		Submission: &submit.Submitter{Pool: s.Pool, Blob: bs},
	}

	deliver := func(pass string) error {
		cli, srv := net.Pipe()
		go func() { _ = subSrv.Serve(ctx, srv) }()
		_ = cli.SetDeadline(time.Now().Add(15 * time.Second))
		c, err := smtpclient.New(ctx, nil, cli, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mail.sender.example"},
			smtpclient.Opts{
				Auth: func(mechs []string, cs *tls.ConnectionState) (sasl.Client, error) {
					return sasl.NewClientSCRAMSHA256("me@sender.example", pass, false), nil
				},
			})
		if err != nil {
			return err
		}
		defer c.Close()
		raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: scram\r\n\r\nvia SCRAM\r\n"
		return c.Deliver(ctx, "me@sender.example", "you@remote.example", int64(len(raw)), strings.NewReader(raw), false, false, false)
	}

	// Correct password: SCRAM proof verifies → enqueued.
	if err := deliver("correct-horse"); err != nil {
		t.Fatalf("SCRAM submission with correct password failed: %v", err)
	}
	var q int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("expected 1 queued outbound after SCRAM auth, got %d", q)
	}

	// Wrong password: SCRAM proof fails → no delivery.
	if err := deliver("wrong"); err == nil {
		t.Fatalf("SCRAM submission with wrong password succeeded — proof check broken")
	}
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("wrong-password SCRAM enqueued a message (queue=%d)", q)
	}

	t.Logf("OK: SMTP submission AUTH SCRAM-SHA-256 accepted correct / rejected wrong password (password never on the wire)")
}
