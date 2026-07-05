package smtpd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestInboundDecision proves P0-1: the inbound decision engine greylists a
// first-seen sender (451), accepts on retry after the delay, rejects a
// known-bad sender by reputation (550), and lets a trusted sender through — all
// at SMTP time, driven by an unmodified smtpclient.
func TestInboundDecision(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, greylist, inbound_reputation RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	// Decider with greylisting on and a tiny delay so the retry passes in-test.
	decider := &inbound.Decider{Pool: s.Pool, GreylistEnabled: true, GreylistDelay: 1 * time.Second}
	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Decider: decider}

	deliver := func(from string) error {
		cConn, sConn := net.Pipe()
		lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 3000}}
		go func() { _ = mx.Serve(ctx, lc) }()
		_ = cConn.SetDeadline(time.Now().Add(20 * time.Second))
		cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			return err
		}
		defer cl.Close()
		raw := "From: " + from + "\r\nTo: u1@example.com\r\nSubject: hi\r\n\r\nhello there\r\n"
		return cl.Deliver(ctx, from, "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false)
	}

	// --- Greylist: first contact from sender.example is deferred (451). ---
	err = deliver("bob@sender.example")
	if err == nil {
		t.Fatalf("first contact was accepted; expected greylist defer (451)")
	}
	if !strings.Contains(err.Error(), "451") && !strings.Contains(strings.ToLower(err.Error()), "greylist") {
		t.Fatalf("first contact error = %v, want 451/greylist", err)
	}

	// --- Retry after the delay: accepted. ---
	time.Sleep(1200 * time.Millisecond)
	if err := deliver("bob@sender.example"); err != nil {
		t.Fatalf("retry after greylist delay failed: %v", err)
	}
	var inbox int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, accID).Scan(&inbox)
	if inbox != 1 {
		t.Fatalf("after greylist pass: inbox has %d, want 1", inbox)
	}

	// --- Known-bad sender: seed junk reputation, expect 550 reject. ---
	if _, err := s.Pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, junk_count) VALUES ($1,'spam.example',5)`, accID); err != nil {
		t.Fatal(err)
	}
	// Pre-pass greylist for spam.example so the reputation reject (not greylist) fires.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO greylist (account_id, sender_domain, client_subnet, allowed_at) VALUES ($1,'spam.example','198.51.100.0/24', now())`, accID); err != nil {
		t.Fatal(err)
	}
	err = deliver("evil@spam.example")
	if err == nil {
		t.Fatalf("known-bad sender was accepted; expected 550 reject")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("known-bad sender error = %v, want 550", err)
	}

	// --- Trusted sender: seed ham reputation, expect direct accept (no greylist). ---
	if _, err := s.Pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, ham_count) VALUES ($1,'good.example',10)`, accID); err != nil {
		t.Fatal(err)
	}
	if err := deliver("alice@good.example"); err != nil {
		t.Fatalf("trusted sender delivery failed: %v", err)
	}

	t.Logf("OK: first-contact greylisted(451)→retry accepted; known-bad reputation rejected(550); trusted sender direct-accepted")
}
