package imapd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/ratelimit"
)

// selfSignedTLS builds a throwaway TLS config for tests (server presents a
// self-signed cert; the client is told to skip verification).
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "octo-mail.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"octo-mail.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// TestTLSPlaintextRejectedThenSTARTTLS proves two WF2 boundaries at once:
//  1. On a TLS-required listener, LOGIN before encryption is refused — the
//     password never crosses the wire in the clear.
//  2. After a real STARTTLS handshake (driven by an unmodified imapclient),
//     the same LOGIN succeeds.
func TestTLSPlaintextRejectedThenSTARTTLS(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir, TLSConfig: selfSignedTLS(t)}

	// --- 1. plaintext LOGIN is refused before STARTTLS ---
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	ic, err := imapclient.New(cc, &imapclient.Opts{Error: func(err error) { panic(err) }})
	if err != nil {
		t.Fatal(err)
	}
	plainLogin := func() (rerr error) {
		defer func() {
			if r := recover(); r != nil {
				rerr = errFromPanic(r)
			}
		}()
		_, e := ic.Login("u1@example.com", "correct-horse")
		return e
	}
	if err := plainLogin(); err == nil {
		t.Fatalf("plaintext LOGIN was accepted on a TLS-required server — credentials would cross the wire in clear")
	}

	// --- 2. after STARTTLS, the same LOGIN succeeds ---
	if _, err := ic.StartTLS(&tls.Config{InsecureSkipVerify: true, ServerName: "octo-mail.test"}); err != nil {
		t.Fatalf("STARTTLS handshake failed: %v", err)
	}
	if _, err := ic.Login("u1@example.com", "correct-horse"); err != nil {
		t.Fatalf("LOGIN after STARTTLS failed: %v", err)
	}
	_ = ic.Close()
	t.Logf("OK: plaintext LOGIN refused pre-TLS; real STARTTLS handshake then LOGIN succeeded")
}

// TestImplicitTLS proves the implicit-TLS listener (993-style): the client wraps
// the socket in TLS before the greeting, then logs in over the encrypted channel.
func TestImplicitTLS(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir, TLSConfig: selfSignedTLS(t)}
	cc, sc := net.Pipe()
	go func() { _ = srv.ServeTLS(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))

	tc := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, ServerName: "octo-mail.test"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("implicit TLS handshake failed: %v", err)
	}
	ic, err := imapclient.New(tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "correct-horse"); err != nil {
		t.Fatalf("LOGIN over implicit TLS failed: %v", err)
	}
	t.Logf("OK: implicit-TLS listener accepted encrypted LOGIN")
}

// TestLoginRateLimit proves the brute-force boundary: after the per-IP window
// limit of failed attempts is exceeded, further LOGINs are refused before the
// credential is even checked — a correct password mid-flood is still refused.
func TestLoginRateLimit(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	// Allow only 3 attempts per minute per IP (all subnet classes).
	lim := &ratelimit.Limiter{WindowLimits: []ratelimit.WindowLimit{{
		Window: time.Minute,
		Limits: [3]int64{3, 3, 3},
	}}}
	srv := &imapd.Server{Dir: dir, LoginLimiter: lim}

	// Each LOGIN uses a fresh connection but the same (pipe) remote IP.
	attempt := func(pass string) error {
		cc, sc := net.Pipe()
		go func() { _ = srv.Serve(ctx, sc) }()
		_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
		ic, err := imapclient.New(cc, &imapclient.Opts{Error: func(err error) { panic(err) }})
		if err != nil {
			return err
		}
		defer ic.Close()
		return func() (rerr error) {
			defer func() {
				if r := recover(); r != nil {
					rerr = errFromPanic(r)
				}
			}()
			_, e := ic.Login("u1@example.com", pass)
			return e
		}()
	}

	// 3 wrong attempts: all rejected (credential check), limiter now saturated.
	for i := 0; i < 3; i++ {
		if err := attempt("wrong"); err == nil {
			t.Fatalf("attempt %d: wrong password accepted", i)
		}
	}
	// 4th attempt with the CORRECT password must still be refused by the limiter.
	if err := attempt("correct-horse"); err == nil {
		t.Fatalf("correct password accepted while rate-limited — brute-force throttle not enforced")
	}
	t.Logf("OK: after 3 attempts the limiter refused even the correct password (brute-force throttle enforced)")
}
