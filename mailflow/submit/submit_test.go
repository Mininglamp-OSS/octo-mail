package submit_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestSubmitQueueDeliver is the WF1 crown proof of the send loop: an account
// submits an outbound message → it is stored in blob + enqueued → the queue
// worker's SMTPDeliverer opens a REAL SMTP session (the smtpclient) to the
// recipient domain's MX (here, octo-mail's own smtpd acting as the remote server) →
// the message lands in the recipient account's change-log, readable back. This
// closes the "can only receive, cannot send" gap end to end.
func TestSubmitQueueDeliver(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	// One tenant, a sender account, and a recipient account on a "remote" domain
	// that our own smtpd will serve as the MX.
	var tenantID, senderID, rcptID, sdom, rdom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'rcpt') RETURNING id`, tenantID).Scan(&rcptID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, tenantID).Scan(&sdom)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'remote.example') RETURNING id`, tenantID).Scan(&rdom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'you')`, tenantID, rdom, rcptID)

	dir := s.NewDirectory()

	// The "remote MX" is octo-mail's own smtpd. The Dialer hands the delivery an
	// in-memory pipe whose server end runs smtpd — a real SMTP conversation.
	mx := &smtpd.Server{Dir: dir, Hostname: "remote.example"}
	dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		cConn, sConn := net.Pipe()
		go func() { _ = mx.Serve(ctx, sConn) }()
		return cConn, dns.Domain{ASCII: "remote.example"}, nil
	}

	// Submit an outbound message from the sender account.
	sub := &submit.Submitter{Pool: s.Pool, Blob: bs}
	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: outbound\r\n\r\nhello over smtp\r\n"
	ids, err := sub.Submit(ctx, tenantID, senderID, "me@sender.example", []string{"you@remote.example"}, []byte(raw))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 enqueued, got %d", len(ids))
	}

	// The worker delivers via a real SMTP session to the "remote" MX.
	deliverer := &submit.SMTPDeliverer{
		Blob: bs, Dial: dialer,
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSSkip,
	}
	w := &queue.Worker{Pool: s.Pool, NodeID: "n1", Deliver: deliverer.Deliver, Batch: 5}
	n, err := w.RunOnce(ctx)
	if err != nil {
		t.Fatalf("worker: %v", err)
	}
	if n != 1 {
		t.Fatalf("worker processed %d, want 1", n)
	}

	// The message must now be in the recipient account's Inbox (delivered over
	// real SMTP), and retired success in the queue.
	var inboxCount int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = s.Pool.QueryRow(ctx, `
			SELECT count(*) FROM messages m
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, rcptID).Scan(&inboxCount)
		if inboxCount == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if inboxCount != 1 {
		t.Fatalf("recipient inbox has %d messages, want 1 (real SMTP delivery failed)", inboxCount)
	}
	var live, retiredSuccess int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&live)
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue_log WHERE kind='delivered'`).Scan(&retiredSuccess)
	if live != 0 || retiredSuccess != 1 {
		t.Fatalf("queue state: live=%d retiredSuccess=%d, want 0/1", live, retiredSuccess)
	}
	t.Logf("OK: submit → enqueue → real SMTP session (smtpclient→smtpd MX) → recipient Inbox; queue retired success")
}
