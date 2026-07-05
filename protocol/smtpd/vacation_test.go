package smtpd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreply"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestVacationAutoReply proves the inbound auto-reply half of JMAP
// VacationResponse: with an enabled vacation config, delivering a message to the
// account enqueues one auto-reply to the sender; a second message from the same
// sender does NOT (dedup); an automated sender (no-reply@) is never answered.
func TestVacationAutoReply(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, vacation_response, vacation_sent RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	// Enable the account's vacation response.
	acc, _, _, err := s.LookupAccountByID(ctx, accID)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.VacationSet(ctx, store.VacationResponse{Enabled: true, Subject: "OOO", TextBody: "I am away."}); err != nil {
		t.Fatal(err)
	}

	responder := &autoreply.Responder{
		Lookup:    s.LookupAccountByID,
		Submitter: &submit.Submitter{Pool: s.Pool, Blob: bs},
	}
	mx := &smtpd.Server{
		Dir: dir, Hostname: "mx.example.com",
		VacationResponder: func(ctx context.Context, accountID int64, sender, recipient string, raw []byte) {
			_ = responder.Respond(ctx, accountID, sender, recipient, raw)
		},
	}

	deliver := func(from string) error {
		cConn, sConn := net.Pipe()
		lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.5"), Port: 3000}}
		go func() { _ = mx.Serve(ctx, lc) }()
		_ = cConn.SetDeadline(time.Now().Add(20 * time.Second))
		cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			return err
		}
		defer cl.Close()
		raw := "From: " + from + "\r\nTo: u1@example.com\r\nSubject: hi\r\n\r\nhello\r\n"
		return cl.Deliver(ctx, from, "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false)
	}

	queueTo := func(rcpt string) int {
		var n int
		s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE rcpt_to=$1`, rcpt).Scan(&n)
		return n
	}

	// First message from a human sender → one auto-reply queued back to them.
	if err := deliver("bob@remote.example"); err != nil {
		t.Fatalf("deliver 1: %v", err)
	}
	// The responder runs synchronously in the delivery path; give the queue a beat.
	waitFor(t, func() bool { return queueTo("bob@remote.example") == 1 }, "auto-reply to bob")

	// Second message from the same sender → no new reply (dedup).
	if err := deliver("bob@remote.example"); err != nil {
		t.Fatalf("deliver 2: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := queueTo("bob@remote.example"); n != 1 {
		t.Fatalf("dedup failed: %d auto-replies to bob, want 1", n)
	}

	// Automated sender is never auto-replied to.
	if err := deliver("no-reply@remote.example"); err != nil {
		t.Fatalf("deliver 3: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := queueTo("no-reply@remote.example"); n != 0 {
		t.Fatalf("auto-replied to an automated sender: %d, want 0", n)
	}

	t.Logf("OK: vacation auto-reply sent once to human sender, deduped on repeat, skipped for no-reply@")
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
