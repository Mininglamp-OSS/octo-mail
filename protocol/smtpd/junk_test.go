package smtpd_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestJunkRoutingOnDelivery proves WF-B end to end: with a per-account junk
// filter trained on spam/ham, a real SMTP delivery of a spammy message is routed
// to the account's Junk mailbox, while a hammy message goes to Inbox. Uses an
// unmodified smtpclient over a pipe.
func TestJunkRoutingOnDelivery(t *testing.T) {
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
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	// Train the account's junk filter (>=50 ham to be significant).
	mgr := junkfilter.NewManager(t.TempDir(), junkfilter.DefaultParams, 0.95)
	defer mgr.Close()
	for i := 0; i < 60; i++ {
		spam := []byte(fmt.Sprintf("Subject: WIN cheap viagra pills\r\n\r\nfree prize cheap meds cheap loans act now winner %d\r\n", i))
		ham := []byte(fmt.Sprintf("Subject: sync notes\r\n\r\nteam here are today's engineering meeting notes and migration plan item %d\r\n", i))
		if err := mgr.Train(ctx, accID, false, spam); err != nil {
			t.Fatal(err)
		}
		if err := mgr.Train(ctx, accID, true, ham); err != nil {
			t.Fatal(err)
		}
	}

	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Junk: mgr}

	deliver := func(raw string) {
		cConn, sConn := net.Pipe()
		go func() { _ = mx.Serve(ctx, sConn) }()
		_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
		cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "sender.test"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		if err := cl.Deliver(ctx, "alice@remote.example", "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false); err != nil {
			t.Fatalf("deliver: %v", err)
		}
	}

	// Deliver a spammy message → Junk; a hammy message → Inbox.
	deliver("From: promo@deals.example\r\nTo: u1@example.com\r\nSubject: WIN cheap viagra pills\r\n\r\nfree prize cheap meds cheap loans act now winner claim\r\n")
	deliver("From: bob@work.example\r\nTo: u1@example.com\r\nSubject: sync notes\r\n\r\nteam here are the engineering meeting notes and migration plan for review\r\n")

	count := func(mailbox string) int {
		var n int
		s.Pool.QueryRow(ctx,
			`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
			 WHERE m.account_id=$1 AND mb.name=$2 AND NOT m.expunged`, accID, mailbox).Scan(&n)
		return n
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (count("Junk")+count("Inbox") < 2) {
		time.Sleep(50 * time.Millisecond)
	}
	if j := count("Junk"); j != 1 {
		t.Fatalf("Junk mailbox has %d messages, want 1 (spam not routed to Junk)", j)
	}
	if in := count("Inbox"); in != 1 {
		t.Fatalf("Inbox has %d messages, want 1 (ham misrouted)", in)
	}
	t.Logf("OK: spam → Junk mailbox, ham → Inbox (per-account bayesian routing on real SMTP delivery)")
}
