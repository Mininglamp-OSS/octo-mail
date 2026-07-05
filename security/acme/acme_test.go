package acme_test

import (
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/security/acme"
	"github.com/mjl-/mox/dns"
)

// TestACMEManagerWiring verifies the ACME/autotls wiring produces a usable
// *tls.Config with an automatic GetCertificate hook, and validates config
// guards. It does NOT perform live certificate issuance — that requires a
// reachable ACME directory (Let's Encrypt/pebble) plus challenge provisioning,
// which is a deployment-layer integration concern, not a unit test.
func TestACMEManagerWiring(t *testing.T) {
	// Missing directory URL / contact are rejected.
	if _, err := acme.New(acme.Config{ContactEmail: "admin@example.com"}); err == nil {
		t.Fatalf("expected error for empty directory URL")
	}
	if _, err := acme.New(acme.Config{DirectoryURL: "https://acme.example/dir"}); err == nil {
		t.Fatalf("expected error for empty contact email")
	}

	m, err := acme.New(acme.Config{
		CacheDir:     t.TempDir(),
		ContactEmail: "admin@example.com",
		DirectoryURL: "https://acme.example/directory", // not contacted until issuance
		Hostnames:    []dns.Domain{{ASCII: "mail.example.com"}},
		Fallback:     dns.Domain{ASCII: "mail.example.com"},
	})
	if err != nil {
		t.Fatalf("acme.New: %v", err)
	}
	cfg := m.TLSConfig()
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("TLSConfig missing GetCertificate hook")
	}
	if m.ACMEChallengeTLSConfig() == nil {
		t.Fatalf("ACME challenge TLS config is nil")
	}

	t.Logf("OK: ACME manager constructed; TLSConfig exposes automatic GetCertificate (live issuance is deployment-layer)")
}
