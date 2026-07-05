// Package acme wires the autotls (ACME/Let's Encrypt) into octo-mail as an optional
// TLS-config source for the SMTP/IMAP/HTTPS listeners. It obtains and renews
// certificates automatically for a set of allowed hostnames.
//
// Honest boundary: real certificate issuance requires a reachable ACME directory
// (Let's Encrypt or a local pebble) plus port 80/443 or DNS-01 provisioning for
// the challenge. TestACMEManagerWiring unit-tests construction (a usable
// *tls.Config with a GetCertificate hook). TestACMELiveIssuance (gated by
// OCTO_MAIL_ACME=1, provisioned via scripts/acme-pebble.sh) drives a real ACME CA:
// it has been observed performing account registration, order, tls-alpn-01
// validation, and certificate issuance against pebble — see that test for the
// documented pebble/x-crypto retrieval boundary.
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/mjl-/autocert"
	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

// Config is the ACME configuration (from cmd/octo-mail env vars).
type Config struct {
	CacheDir     string          // directory for account key + certificate cache
	ContactEmail string          // ACME account contact
	DirectoryURL string          // ACME directory (Let's Encrypt prod/staging, or pebble)
	Hostnames    []dns.Domain    // hostnames we may obtain certificates for
	Fallback     dns.Domain      // fallback hostname for SNI-less / unknown-SNI clients
	Resolver     dns.Resolver    // resolver for hostname validation (nil = default)
	Shutdown     <-chan struct{} // closed to stop issuing during shutdown
}

// Manager wraps an autotls.Manager and exposes a *tls.Config.
type Manager struct {
	m        *autotls.Manager
	fallback dns.Domain
}

// New constructs the ACME manager and registers the allowed hostnames.
func New(cfg Config) (*Manager, error) {
	if cfg.DirectoryURL == "" {
		return nil, fmt.Errorf("acme: empty directory URL")
	}
	if cfg.ContactEmail == "" {
		return nil, fmt.Errorf("acme: empty contact email")
	}
	log := mlog.New("acme", nil)
	getPrivKey := func(host string, keyType autocert.KeyType) (crypto.Signer, error) {
		// Generate a fresh per-host key of the requested type. autotls/autocert
		// caches the resulting certificate (with this key) in CacheDir, so a new
		// key is only generated when there is no cached cert for the host.
		switch keyType {
		case autocert.KeyRSA2048:
			return rsa.GenerateKey(rand.Reader, 2048)
		case autocert.KeyECDSAP256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		default:
			return nil, fmt.Errorf("acme: unsupported key type %v", keyType)
		}
	}
	m, err := autotls.Load(log, "octo-mail", cfg.CacheDir, cfg.ContactEmail, cfg.DirectoryURL, "", nil, getPrivKey, cfg.Shutdown)
	if err != nil {
		return nil, fmt.Errorf("acme: load manager: %w", err)
	}
	if len(cfg.Hostnames) > 0 {
		hs := map[dns.Domain]struct{}{}
		for _, h := range cfg.Hostnames {
			hs[h] = struct{}{}
		}
		res := cfg.Resolver
		if res == nil {
			res = dns.StrictResolver{Pkg: "acme"}
		}
		// checkHosts=false: don't require live DNS at startup (validated at issuance).
		m.SetAllowedHostnames(log, res, hs, nil, false)
	}
	return &Manager{m: m, fallback: cfg.Fallback}, nil
}

// TLSConfig returns a *tls.Config whose GetCertificate obtains/renews certs via
// ACME. Suitable for IMAP/SMTP implicit TLS and the HTTPS listeners.
func (m *Manager) TLSConfig() *tls.Config {
	return m.m.TLSConfig(m.fallback, true, true)
}

// ACMEChallengeTLSConfig returns the TLS config that answers ACME tls-alpn-01
// challenges on port 443; serve it there so issuance can complete.
func (m *Manager) ACMEChallengeTLSConfig() *tls.Config {
	return m.m.ACMETLSConfig
}

// SetACMEHTTPClient overrides the HTTP client the ACME account uses to reach the
// directory. Used by the pebble integration test to trust pebble's self-signed
// ACME directory; production leaves the default (system trust for Let's Encrypt).
func (m *Manager) SetACMEHTTPClient(hc *http.Client) {
	m.m.Manager.Client.HTTPClient = hc
}
