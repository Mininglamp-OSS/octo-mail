package smtpd_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

// TestSubmissionOverSMTP proves the submission(587) path end to end: a real SMTP
// client (the smtpclient) authenticates (AUTH PLAIN) and submits an outbound
// message to octo-mail's smtpd in submission mode → it is enqueued → the queue
// worker delivers it via a real SMTP session to the recipient's MX (smtpd
// receive mode) → lands in the recipient's Inbox.
func TestSubmissionOverSMTP(t *testing.T) {
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
	var tenantID, senderID, rcptID, sdom, rdom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'rcpt') RETURNING id`, tenantID).Scan(&rcptID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, tenantID).Scan(&sdom)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'remote.example') RETURNING id`, tenantID).Scan(&rdom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'you')`, tenantID, rdom, rcptID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)

	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "irrelevant"); err != nil {
		t.Fatal(err)
	}

	// Submission listener (587-style): requires AUTH, enqueues outbound.
	subSrv := &smtpd.Server{
		Dir:        dir,
		Hostname:   "mail.sender.example",
		Submission: &submit.Submitter{Pool: s.Pool, Blob: bs},
	}
	subCli, subConn := net.Pipe()
	go func() { _ = subSrv.Serve(ctx, subConn) }()
	_ = subCli.SetDeadline(time.Now().Add(15 * time.Second))

	cl, err := smtpclient.New(ctx, nil, subCli,
		smtpclient.TLSSkip, false,
		dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mail.sender.example"},
		smtpclient.Opts{
			Auth: func(mechs []string, cs *tls.ConnectionState) (sasl.Client, error) {
				return sasl.NewClientPlain("me@sender.example", "irrelevant"), nil
			},
		})
	if err != nil {
		t.Fatalf("smtpclient new (auth): %v", err)
	}
	defer cl.Close()

	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: submitted\r\n\r\nvia 587\r\n"
	if err := cl.Deliver(ctx, "me@sender.example", "you@remote.example", int64(len(raw)), strings.NewReader(raw), false, false, false); err != nil {
		t.Fatalf("submission deliver: %v", err)
	}

	// One queue row enqueued for outbound.
	var q int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("expected 1 queued outbound, got %d", q)
	}

	// The MX (receive-mode smtpd) for remote.example.
	mx := &smtpd.Server{Dir: dir, Hostname: "remote.example"}
	dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		mc, ms := net.Pipe()
		go func() { _ = mx.Serve(ctx, ms) }()
		return mc, dns.Domain{ASCII: "remote.example"}, nil
	}
	deliverer := &submit.SMTPDeliverer{Blob: bs, Dial: dialer, EHLOHostname: dns.Domain{ASCII: "sender.example"}, TLSMode: smtpclient.TLSSkip}
	w := &queue.Worker{Pool: s.Pool, NodeID: "n1", Deliver: deliverer.Deliver, Batch: 5}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("worker: %v", err)
	}

	// Recipient Inbox has the message.
	var inbox int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, rcptID).Scan(&inbox)
		if inbox == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if inbox != 1 {
		t.Fatalf("recipient inbox has %d, want 1 (submission→queue→delivery failed)", inbox)
	}
	t.Logf("OK: AUTH+submission over SMTP → enqueue → real delivery to MX → recipient Inbox")
}
