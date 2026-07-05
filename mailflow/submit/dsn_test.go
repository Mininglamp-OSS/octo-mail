package submit_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
)

// TestDSNOnPermanentFailure proves the bounce path: an outbound message that
// permanently fails delivery generates a DSN (RFC 3464, via the dsn library) that lands
// in the sender's Inbox, readable back.
func TestDSNOnPermanentFailure(t *testing.T) {
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
	var tenantID, senderID, sdom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, tenantID).Scan(&sdom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)

	// Submit to an unreachable recipient.
	sub := &submit.Submitter{Pool: s.Pool, Blob: bs}
	raw := "From: me@sender.example\r\nTo: nobody@unreachable.example\r\nSubject: will bounce\r\n\r\nbody\r\n"
	ids, err := sub.Submit(ctx, tenantID, senderID, "me@sender.example", []string{"nobody@unreachable.example"}, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Force fail-fast: max_attempts=1.
	if _, err := s.Pool.Exec(ctx, `UPDATE queue SET max_attempts=1 WHERE id=$1`, ids[0]); err != nil {
		t.Fatal(err)
	}

	dsnGen := &submit.DSNGenerator{Opener: s, Hostname: dns.Domain{ASCII: "sender.example"}}
	w := &queue.Worker{
		Pool: s.Pool, NodeID: "n1", Batch: 5,
		Deliver:  func(ctx context.Context, m queue.Msg) error { return fmt.Errorf("simulated permanent failure") },
		OnFailed: dsnGen.Generate,
	}
	// One pass: attempt=1 reaches max_attempts=1 → permanent fail → DSN.
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("worker: %v", err)
	}

	// Sender's Inbox must contain the bounce.
	var count int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, senderID).Scan(&count)
	if count != 1 {
		t.Fatalf("sender inbox has %d messages, want 1 (the DSN)", count)
	}

	// Confirm the queue message is retired as failure.
	var failed int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue_log WHERE kind='failed'`).Scan(&failed)
	if failed != 1 {
		t.Fatalf("expected 1 failed-retired queue message, got %d", failed)
	}
	_ = strings.TrimSpace
	t.Logf("OK: permanent delivery failure generated a DSN into the sender's Inbox; queue retired as failure")
}

// TestDSNNullSenderNoDoubleBounce proves the double-bounce guard: a failed message
// with a null return-path (empty MailFrom — it is itself a bounce/notification)
// generates NO DSN (returns nil, nothing lands), preventing mail loops.
func TestDSNNullSenderNoDoubleBounce(t *testing.T) {
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
	var tenantID, senderID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)

	dsnGen := &submit.DSNGenerator{Opener: s, Hostname: dns.Domain{ASCII: "sender.example"}}
	// A bounce message itself failing: null MailFrom. Generate must be a no-op.
	m := queue.Msg{TenantID: tenantID, AccountID: senderID, MailFrom: "", RcptTo: "orig@remote.example", BlobRef: "x", Size: 1}
	if err := dsnGen.Generate(ctx, m); err != nil {
		t.Fatalf("null-sender DSN should be a silent no-op, got err: %v", err)
	}
	var count int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1`, senderID).Scan(&count)
	if count != 0 {
		t.Fatalf("null-sender generated %d messages, want 0 (no double bounce)", count)
	}
	t.Logf("OK: null return-path message produced no DSN (double-bounce prevented)")
}
