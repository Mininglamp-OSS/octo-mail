package acme_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/security/acme"
	"github.com/mjl-/autocert"
	"github.com/mjl-/mox/dns"
	xacme "golang.org/x/crypto/acme"
)

// memCache is an in-memory autocert.Cache for unit tests (no Postgres, no CA).
type memCache struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemCache() *memCache { return &memCache{m: map[string][]byte{}} }

func (c *memCache) Get(_ context.Context, k string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.m[k]; ok {
		return v, nil
	}
	return nil, autocert.ErrCacheMiss
}
func (c *memCache) Put(_ context.Context, k string, v []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = append([]byte(nil), v...)
	return nil
}
func (c *memCache) Delete(_ context.Context, k string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
	return nil
}

// seedKeycertKey writes a self-signed cert for host into the cache under the given
// cache key, in autocert's keycert format (PEM private key then PEM certificate),
// as CertAvailable/cacheGet expect. Not CA-signed — those paths only check expiry.
func seedKeycertKey(t *testing.T, c *memCache, cacheKey, host string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := c.Put(context.Background(), cacheKey, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// seedRSAKeycert is like seedKeycertKey but with an RSA key, for exercising the
// follower's "+rsa" variant selection with a legacy (RSA-kx) client.
func seedRSAKeycert(t *testing.T, c *memCache, cacheKey, host string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := c.Put(context.Background(), cacheKey, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func newClusteredManager(t *testing.T, cache autocert.Cache, host string) *acme.Manager {
	t.Helper()
	m, err := acme.New(acme.Config{
		CacheDir:     t.TempDir(),
		ContactEmail: "admin@example.com",
		// Unreachable directory: any real order attempt fails fast (TCP refused),
		// which is how we detect that a follower did NOT try to issue.
		DirectoryURL: "https://127.0.0.1:1/directory",
		Hostnames:    []dns.Domain{{ASCII: host}},
		Fallback:     dns.Domain{ASCII: host},
		Cache:        cache,
	})
	if err != nil {
		t.Fatalf("acme.New: %v", err)
	}
	return m
}

// handshake drives a real client TLS handshake against serverCfg over an in-memory
// pipe (which populates the server hello's Conn + context, unlike a synthetic
// ClientHelloInfo). Returns the client-side handshake error (nil on success) and,
// on success, the negotiated ALPN proto. A per-call deadline guards against a
// server GetCertificate that blocks (e.g. a regression that tries to order).
func handshake(t *testing.T, serverCfg *tls.Config, sni string, clientProtos []string) (error, string) {
	t.Helper()
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()
	_ = cconn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = sconn.SetDeadline(time.Now().Add(5 * time.Second))

	srv := tls.Server(sconn, serverCfg)
	go func() { _ = srv.HandshakeContext(context.Background()) }()

	client := tls.Client(cconn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // self-signed test certs; we assert reachability, not chain
		NextProtos:         clientProtos,
		MinVersion:         tls.VersionTLS12,
	})
	err := client.HandshakeContext(context.Background())
	if err != nil {
		return err, ""
	}
	return nil, client.ConnectionState().NegotiatedProtocol
}

// TestClusteredFollowerServesCachedNeverOrders proves the leader-gating core over a
// REAL handshake: a non-leader serves a cert already in the shared cache, but when
// NOTHING usable is cached (neither the SNI host nor the fallback) the handshake
// fails (unrecognized_name) WITHOUT trying to order — a bounded deadline catches a
// regression that would block on the unreachable directory.
func TestClusteredFollowerServesCachedNeverOrders(t *testing.T) {
	cache := newMemCache()
	const served = "served.example"
	seedKeycertKey(t, cache, served, served)

	// Manager whose fallback is `served` (cached) — an allowlisted, cached host.
	m := newClusteredManager(t, cache, served)
	cfg := m.HTTPSTLSConfig()

	// Follower serves a cached, allowlisted host: handshake succeeds.
	if err, _ := handshake(t, cfg, served, []string{"http/1.1"}); err != nil {
		t.Fatalf("follower handshake for cached host failed: %v", err)
	}

	// A separate manager whose host AND fallback are an un-cached host: a follower
	// has nothing to serve (SNI not cached; fallback not cached) → no cert, fast, no
	// ordering. (With the fallback also empty in cache, the SNI-fallback path can't
	// rescue it, so this isolates the genuine no-serve case.)
	const absent = "absent.example"
	m2 := newClusteredManager(t, cache, absent) // fallback=absent, not in cache
	start := time.Now()
	err, _ := handshake(t, m2.HTTPSTLSConfig(), absent, []string{"http/1.1"})
	if err == nil {
		t.Fatal("follower handshake for an un-cached host succeeded — expected no cert (serve-only)")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("follower handshake for an un-cached host was slow — it likely tried to order (should be cache-only)")
	}
	t.Logf("OK: follower serves cached certs and returns no-cert (fast, no ordering) when nothing usable is cached: %v", err)
}

// TestFollowerFallbackForUnknownSNI proves the #44 fix: a follower mirrors the
// leader/autotls unknown-SNI fallback. A client sending an SNI that is NOT the
// allowlisted host (e.g. a bare domain / wrong name) is served the FALLBACK host's
// cached cert — the same cert the leader would serve — instead of unrecognized_name.
func TestFollowerFallbackForUnknownSNI(t *testing.T) {
	cache := newMemCache()
	const fallback = "mx.example"
	seedKeycertKey(t, cache, fallback, fallback) // only the fallback host is cached

	m := newClusteredManager(t, cache, fallback) // Hostnames + Fallback = mx.example
	cfg := m.HTTPSTLSConfig()

	// Client sends an unknown (non-allowlisted) SNI; the follower must fall back to
	// the cached fallback host's cert and complete the handshake.
	if err, _ := handshake(t, cfg, "not-allowlisted.example", []string{"http/1.1"}); err != nil {
		t.Fatalf("follower did not fall back for an unknown SNI (would diverge from the leader): %v", err)
	}
	t.Logf("OK: follower serves the fallback host cert for an unknown SNI (matches leader/autotls behavior)")
}

// TestServingConfigNextProtos proves the HTTPS config advertises h2/http1.1/acme-tls/1
// (so the same :443 door serves web traffic and answers tls-alpn-01), while the MAIL
// config advertises NO ALPN — mail listeners never receive a tls-alpn-01 challenge,
// and advertising only acme-tls/1 would break a mail client offering its own ALPN.
func TestServingConfigNextProtos(t *testing.T) {
	m := newClusteredManager(t, newMemCache(), "x.example")
	https := m.HTTPSTLSConfig().NextProtos
	mail := m.MailTLSConfig().NextProtos

	if !contains(https, xacme.ALPNProto) || !contains(https, "h2") || !contains(https, "http/1.1") {
		t.Fatalf("HTTPS NextProtos = %v, want h2/http1.1/acme-tls/1", https)
	}
	if len(mail) != 0 {
		t.Fatalf("mail NextProtos = %v, want empty (mail listeners must not force ALPN / advertise acme-tls/1)", mail)
	}
	t.Logf("OK: HTTPS advertises h2/http1.1/acme-tls/1; mail advertises no ALPN")
}

// TestFollowerAnswersTLSALPNChallenge proves a tls-alpn-01 challenge handshake is
// answered on a follower (bypassing the serve-only gate) from the shared cache — so
// any node's :443 can complete a validation the leader started. A CA validation
// client offers ONLY the acme-tls/1 proto; we assert the handshake negotiates it.
func TestFollowerAnswersTLSALPNChallenge(t *testing.T) {
	cache := newMemCache()
	const host = "chal.example"
	seedKeycertKey(t, cache, host+"+token", host) // token cache key

	m := newClusteredManager(t, cache, host) // not leader
	cfg := m.HTTPSTLSConfig()
	err, proto := handshake(t, cfg, host, []string{xacme.ALPNProto})
	if err != nil {
		t.Fatalf("follower tls-alpn-01 handshake failed: %v", err)
	}
	if proto != xacme.ALPNProto {
		t.Fatalf("negotiated proto = %q, want %q", proto, xacme.ALPNProto)
	}
	t.Logf("OK: a follower answers a tls-alpn-01 challenge from the shared cache (challenge routing)")
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestFollowerServesRSAVariantForLegacyClient proves the direct follower serve
// path selects the "+rsa" cached variant for a client without ECDSA capability —
// so warming/serving isn't limited to the ECDSA cert (the review's #32-R2 concern).
// A client offering only an RSA cipher suite must get the cert cached under
// "<host>+rsa"; the ECDSA "<host>" entry is deliberately left absent so a wrong
// selection would fail the handshake.
func TestFollowerServesRSAVariantForLegacyClient(t *testing.T) {
	cache := newMemCache()
	const host = "legacy.example"
	seedRSAKeycert(t, cache, host+"+rsa", host) // only the RSA variant is cached

	m := newClusteredManager(t, cache, host) // follower
	cfg := m.HTTPSTLSConfig()

	// RSA-only client (no ECDSA sig schemes / curves / suites) → serveCachedCert
	// must look up "<host>+rsa" and serve it.
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()
	_ = cconn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = sconn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _ = tls.Server(sconn, cfg).HandshakeContext(context.Background()) }()
	client := tls.Client(cconn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		// An ECDHE_RSA suite: RSA server cert, no ECDSA capability → supportsECDSA is
		// false → serveCachedCert selects the "+rsa" variant. (Avoids the TLS-1.2
		// RSA-key-exchange suites Go disables by default.)
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		MaxVersion:   tls.VersionTLS12, // TLS1.3 ignores CipherSuites; pin 1.2 to force the RSA-cert path
		MinVersion:   tls.VersionTLS12,
	})
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("legacy RSA client handshake failed — follower did not serve the +rsa variant: %v", err)
	}
	t.Logf("OK: follower serves the +rsa cached variant to a legacy (non-ECDSA) client")
}

// TestFollowerRejectsExpiredCachedCert proves the direct serve path does NOT serve
// an expired cached cert (it returns no-cert → unrecognized_name), so a stale entry
// can't be served past its validity.
func TestFollowerRejectsExpiredCachedCert(t *testing.T) {
	cache := newMemCache()
	const host = "expired.example"
	seedExpiredKeycert(t, cache, host)

	m := newClusteredManager(t, cache, host) // follower
	err, _ := handshake(t, m.HTTPSTLSConfig(), host, []string{"http/1.1"})
	if err == nil {
		t.Fatal("follower served an expired cached cert — expected no-cert (unrecognized_name)")
	}
	t.Logf("OK: follower does not serve an expired cached cert: %v", err)
}

// seedExpiredKeycert seeds a cert whose validity is entirely in the past.
func seedExpiredKeycert(t *testing.T, c *memCache, host string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	keyDER, _ := x509.MarshalECPrivateKey(key)
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := c.Put(context.Background(), host, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}
