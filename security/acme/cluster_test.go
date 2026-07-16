package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
)

// recordingSolver fails the test if the serving path ever invokes it — proving
// that followers/serving never issue.
type recordingSolver struct {
	t        *testing.T
	presents int
}

func (s *recordingSolver) Present(ctx context.Context, fqdn, value string) error {
	s.presents++
	s.t.Errorf("serving path called DNSSolver.Present(%q) — must never issue", fqdn)
	return nil
}
func (s *recordingSolver) CleanUp(ctx context.Context, fqdn, value string) error { return nil }

// selfSignedBundle builds a cert bundle (encodeBundle format) for host, valid for
// the given duration, so tests can seed the shared store without a live CA.
func selfSignedBundle(t *testing.T, host string, validFor time.Duration) []byte {
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
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := encodeBundle(key, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func newTestCluster(t *testing.T, ctx context.Context, host string, solver DNSSolver) *ClusterManager {
	t.Helper()
	cm, err := NewCluster(ClusterConfig{
		Pool:         openACMEPool(t, ctx),
		DirectoryURL: "https://acme.example.test/dir",
		ContactEmail: "ops@example.test",
		Hostnames:    []dns.Domain{{ASCII: host}},
		Solver:       solver,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

// TestClusterServesFromSharedStoreWithoutIssuing seeds a cert into the shared
// store, then checks the serving GetCertificate returns it — and never calls the
// DNS solver (i.e. serving does not issue). This is the follower/serve-only path.
func TestClusterServesFromSharedStoreWithoutIssuing(t *testing.T) {
	ctx := context.Background()
	const host = "mail.example.test"
	solver := &recordingSolver{t: t}
	cm := newTestCluster(t, ctx, host, solver)

	// Seed a valid cert as if the leader had issued it.
	if err := cm.cache.Put(ctx, certName(host), selfSignedBundle(t, host, 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Refresher picks it up.
	if n := cm.RefreshOnce(ctx); n != 1 {
		t.Fatalf("RefreshOnce reloaded %d, want 1", n)
	}

	// GetCertificate serves it for the right SNI.
	got, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Leaf == nil || got.Leaf.Subject.CommonName != host {
		t.Fatalf("served cert = %+v, want leaf CN %q", got, host)
	}

	// Unknown SNI → nil cert, nil error (no issuance, "unrecognized name").
	if c, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: "other.example.test"}); err != nil || c != nil {
		t.Fatalf("unknown SNI: got (%v,%v), want (nil,nil)", c, err)
	}

	if solver.presents != 0 {
		t.Fatalf("solver invoked %d times on serving path, want 0", solver.presents)
	}
}

// TestNeedsRenewal covers the expiry decision that drives the leader loop.
func TestNeedsRenewal(t *testing.T) {
	ctx := context.Background()
	const host = "mail.example.test"
	cm := newTestCluster(t, ctx, host, &recordingSolver{t: t})

	// No stored cert → needs renewal.
	if !cm.needsRenewal(ctx, host) {
		t.Fatal("missing cert should need renewal")
	}
	// Fresh 90-day cert → no renewal (renewBefore defaults to 30 days).
	if err := cm.cache.Put(ctx, certName(host), selfSignedBundle(t, host, 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if cm.needsRenewal(ctx, host) {
		t.Fatal("90-day cert should not need renewal")
	}
	// Cert within the renew window (10 days left) → needs renewal.
	if err := cm.cache.Put(ctx, certName(host), selfSignedBundle(t, host, 10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !cm.needsRenewal(ctx, host) {
		t.Fatal("10-day cert should need renewal (within 30-day window)")
	}
}
