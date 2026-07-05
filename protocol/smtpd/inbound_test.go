package smtpd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

// TestInboundAuthentication proves WF-A: a message delivered over real SMTP is
// authenticated (SPF pass on the envelope, DKIM pass on a signed message, DMARC
// aligned pass), and the results are stored as an Authentication-Results header
// plus a Received header in the DB prefix (not the immutable body). It also
// proves a forged message (no SPF authorization, no DKIM) records failing
// results — the receiver can now tell real from fake.
func TestInboundAuthentication(t *testing.T) {
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

	// Sender domain sender.example: SPF authorizes 10.0.0.9, and a DKIM key.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dkimTXT := "v=DKIM1;k=ed25519;p=" + base64.StdEncoding.EncodeToString(pub)
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"sender.example.":                {"v=spf1 ip4:10.0.0.9 -all"},
			"sel._domainkey.sender.example.": {dkimTXT},
			"_dmarc.sender.example.":         {"v=DMARC1; p=reject"},
			"_dmarc.bank.example.":           {"v=DMARC1; p=reject"},
		},
		PTR: map[string][]string{
			"9.0.0.10.in-addr.arpa.": {"mail.sender.example."},
		},
		A: map[string][]string{
			"mail.sender.example.": {"10.0.0.9"},
		},
		AllAuthentic: true,
	}
	auth := &inbound.Authenticator{Resolver: resolver}

	// The MX server with inbound authentication enabled. We inject the client IP
	// via a pipe wrapper that reports 10.0.0.9 as RemoteAddr.
	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Auth: auth}

	deliver := func(t *testing.T, raw string) {
		t.Helper()
		cConn, sConn := net.Pipe()
		lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 12345}}
		go func() { _ = mx.Serve(ctx, lc) }()
		_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
		cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "mail.sender.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			t.Fatalf("smtpclient: %v", err)
		}
		defer cl.Close()
		if err := cl.Deliver(ctx, "bob@sender.example", "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false); err != nil {
			t.Fatalf("deliver: %v", err)
		}
	}

	// --- Legitimate: SPF-authorized IP + DKIM signature. ---
	body := "From: bob@sender.example\r\nTo: u1@example.com\r\nSubject: legit\r\nDate: Wed, 01 Jul 2026 10:00:00 +0000\r\nMessage-Id: <legit@sender.example>\r\n\r\nhello\r\n"
	sel := dkim.Selector{Hash: "sha256", HeaderRelaxed: true, BodyRelaxed: true,
		Headers:    []string{"From", "To", "Subject", "Date", "Message-Id"},
		PrivateKey: priv, Domain: dns.Domain{ASCII: "sel"}}
	hdr, err := dkim.Sign(ctx, nil, smtp.Localpart("bob"), dns.Domain{ASCII: "sender.example"}, []dkim.Selector{sel}, false, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, hdr+body)

	prefix := latestPrefix(t, s, ctx, accID)
	if !strings.Contains(prefix, "Received: from") {
		t.Fatalf("no Received header stored:\n%s", prefix)
	}
	if !strings.Contains(prefix, "Authentication-Results:") {
		t.Fatalf("no Authentication-Results header stored:\n%s", prefix)
	}
	if !strings.Contains(prefix, "spf=pass") {
		t.Fatalf("expected spf=pass in:\n%s", prefix)
	}
	if !strings.Contains(prefix, "dkim=pass") {
		t.Fatalf("expected dkim=pass in:\n%s", prefix)
	}
	if !strings.Contains(prefix, "dmarc=pass") {
		t.Fatalf("expected dmarc=pass in:\n%s", prefix)
	}

	// --- Forged: From: ceo@bank.example, but sent from sender.example's infra
	// and unsigned. SPF passes on the ENVELOPE (bob@sender.example) but is NOT
	// aligned with the From-header domain bank.example, and there is no DKIM for
	// bank.example → DMARC fails. With RejectDMARCFail the message is rejected. ---
	mxReject := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Auth: auth, RejectDMARCFail: true}
	forged := "From: ceo@bank.example\r\nTo: u1@example.com\r\nSubject: wire money\r\nMessage-Id: <forge@bank.example>\r\n\r\nsend $1M\r\n"

	cConn, sConn := net.Pipe()
	lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 12345}}
	go func() { _ = mxReject.Serve(ctx, lc) }()
	_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
	cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
		dns.Domain{ASCII: "mail.sender.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	derr := cl.Deliver(ctx, "bob@sender.example", "u1@example.com", int64(len(forged)), strings.NewReader(forged), false, false, false)
	if derr == nil {
		t.Fatalf("forged (DMARC-misaligned) message was accepted; expected rejection")
	}
	if !strings.Contains(derr.Error(), "DMARC") && !strings.Contains(derr.Error(), "550") {
		t.Fatalf("forged message rejected but not for DMARC: %v", derr)
	}
	t.Logf("OK: legit → spf=pass/dkim=pass/dmarc=pass + Received/AR stored; forged (From-spoof) → rejected by DMARC (%v)", derr)
}

// ipConn wraps a net.Conn to report a chosen RemoteAddr (net.Pipe reports a
// non-TCP addr, so the server can't see a client IP otherwise).
type ipConn struct {
	net.Conn
	remote net.Addr
}

func (c *ipConn) RemoteAddr() net.Addr { return c.remote }

func latestPrefix(t *testing.T, s *postgres.Store, ctx context.Context, accID int64) string {
	t.Helper()
	var prefix []byte
	err := s.Pool.QueryRow(ctx,
		`SELECT msg_prefix FROM messages WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, accID).Scan(&prefix)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	return string(prefix)
}
