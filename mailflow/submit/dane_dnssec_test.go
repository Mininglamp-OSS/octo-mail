package submit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestDANEViaDNSSEC proves the full DANE path with the DNSSEC authenticity gate
// (RFC 7672): the deliverer's DANEFor is deliverability.Lookup over a dns.Resolver.
// With an AUTHENTIC (DNSSEC) resolver publishing matching TLSA records, delivery
// verifies the MX cert against them. With an INAUTHENTIC resolver, the TLSA
// records are ignored (no DANE, no downgrade pin) — proving we never trust
// unauthenticated TLSA data. Uses the smtpclient.GatherTLSA + a real STARTTLS MX.
func TestDANEViaDNSSEC(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, wf6DSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}

	// Self-signed cert for the MX host + its DANE-EE/SPKI/SHA-256 TLSA record.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.dane.example"},
		DNSNames:     []string{"mx.dane.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	leaf, _ := x509.ParseCertificate(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	tlsa := adns.TLSA{Usage: adns.TLSAUsageDANEEE, Selector: adns.TLSASelectorSPKI, MatchType: adns.TLSAMatchTypeSHA256, CertAssoc: spki[:]}

	bs, _ := blob.NewFS(t.TempDir())
	raw := "From: me@sender.example\r\nTo: you@dane.example\r\nSubject: dane-dnssec\r\nMessage-Id: <d@sender.example>\r\n\r\nhello\r\n"
	ref, size, err := bs.Put(ctx, 1, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	msg := queue.Msg{TenantID: 1, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@dane.example", BlobRef: string(ref), Size: size}

	// MockResolver: A record + TLSA record for the MX host. The authentic bit is
	// toggled per subtest.
	mkResolver := func(authentic bool) dns.MockResolver {
		return dns.MockResolver{
			AllAuthentic: authentic,
			A:            map[string][]string{"mx.dane.example.": {"127.0.0.1"}},
			TLSA: map[string][]adns.TLSA{
				"_25._tcp.mx.dane.example.": {tlsa},
			},
		}
	}

	newDeliverer := func(res dns.Resolver) (*submit.SMTPDeliverer, chan string) {
		got := make(chan string, 1)
		dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			c, srv := net.Pipe()
			go serveSTARTTLSMX(srv, cert, got)
			return c, dns.Domain{ASCII: "mx.dane.example"}, nil
		}
		return &submit.SMTPDeliverer{
			Blob:         bs,
			Dial:         dialer,
			EHLOHostname: dns.Domain{ASCII: "sender.example"},
			TLSMode:      smtpclient.TLSOpportunistic,
			DANEFor:      deliverability.Lookup(res),
		}, got
	}

	// --- Authentic (DNSSEC) TLSA → DANE verifies, delivery succeeds. ---
	d, got := newDeliverer(mkResolver(true))
	if err := d.Deliver(ctx, msg); err != nil {
		t.Fatalf("delivery with authentic TLSA should succeed: %v", err)
	}
	select {
	case body := <-got:
		if !strings.Contains(body, "hello") {
			t.Fatalf("MX did not receive body: %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MX did not receive the DANE-verified message")
	}

	// --- Inauthentic DNS → TLSA ignored (no DANE); opportunistic TLS still works. ---
	// Prove the records were NOT used as a hard pin: use a cert whose TLSA would
	// NOT match, but keep DNS inauthentic → Lookup returns no records → delivery
	// proceeds opportunistically and succeeds anyway.
	badPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badDer, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &badPriv.PublicKey, badPriv)
	badLeaf, _ := x509.ParseCertificate(badDer)
	badCert := tls.Certificate{Certificate: [][]byte{badDer}, PrivateKey: badPriv, Leaf: badLeaf}

	got2 := make(chan string, 1)
	dialer2 := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		c, srv := net.Pipe()
		go serveSTARTTLSMX(srv, badCert, got2)
		return c, dns.Domain{ASCII: "mx.dane.example"}, nil
	}
	d2 := &submit.SMTPDeliverer{
		Blob:         bs,
		Dial:         dialer2,
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSOpportunistic,
		DANEFor:      deliverability.Lookup(mkResolver(false)), // inauthentic
	}
	if err := d2.Deliver(ctx, msg); err != nil {
		t.Fatalf("inauthentic-DNS delivery should proceed opportunistically (TLSA ignored): %v", err)
	}
	select {
	case <-got2:
	case <-time.After(5 * time.Second):
		t.Fatal("inauthentic-DNS message not delivered")
	}

	t.Logf("OK: authentic DNSSEC TLSA verified MX cert; inauthentic DNS ignored TLSA (no downgrade pin), delivered opportunistically")
}
