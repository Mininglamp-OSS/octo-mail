// Package acme wires the autotls (ACME/Let's Encrypt) into octo-mail as an optional
// TLS-config source for the SMTP/IMAP/HTTPS listeners. It obtains and renews
// certificates automatically for a set of allowed hostnames.
//
// Multi-node (issue #32): when a shared autocert.Cache is supplied (Config.Cache,
// e.g. the Postgres-backed storage/postgres.AcmeCache), the whole stateless cluster
// shares ONE ACME account key + certificate set. Issuance is leader-gated: only the
// node the caller marks leader (SetLeader) orders certs; followers serve certs — and
// answer tls-alpn-01 challenges — from the shared cache and never order. Because the
// autocert account key and the tls-alpn-01 token certs also live in the shared
// cache, a challenge validation the leader started can be completed by ANY node
// whose :443 receives the CA's connection. Without a shared cache the manager is
// single-node only (the legacy H17 behavior): the account key + certs are a
// node-local directory, so running built-in ACME on multiple nodes makes each
// register its own account and race to order the same certs.
//
// Honest boundary: real certificate issuance requires a reachable ACME directory
// (Let's Encrypt or a local pebble) plus port 443 (tls-alpn-01) or DNS-01
// provisioning for the challenge. TestACMEManagerWiring unit-tests construction (a
// usable *tls.Config with a GetCertificate hook). TestACMELiveIssuance (gated by
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
	"strings"
	"sync/atomic"

	xacme "golang.org/x/crypto/acme"

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
	// Cache, when non-nil, backs the ACME account key + certs + tls-alpn-01 token
	// certs with SHARED storage (e.g. Postgres) instead of the node-local dir,
	// enabling leader-gated cluster issuance. nil = legacy single-node (node-local).
	Cache autocert.Cache
}

// Manager wraps an autotls.Manager and exposes leader-gated *tls.Config builders.
type Manager struct {
	m        *autotls.Manager
	fallback dns.Domain
	log      mlog.Log
	// clustered is true when a shared Cache was supplied (multi-node leader-gated
	// mode). isLeader is consulted by the serving configs: a follower serves cached
	// certs but never orders. In single-node mode (clustered=false) the gate is a
	// no-op and this node always issues.
	clustered bool
	isLeader  atomic.Bool
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
		// caches the resulting certificate (with this key) in the cache, so a new
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
	mgr := &Manager{m: m, fallback: cfg.Fallback, log: log}
	if cfg.Cache != nil {
		// Route the account key, issued certs, and tls-alpn-01 token certs through
		// the shared cache. Nilling Client.Key makes autocert derive/persist the ACME
		// ACCOUNT key from the cache (accountKey() is used only when Client.Key is
		// nil); autotls.Load set it from the local file, which we override here. Done
		// before any listener serves, so autocert has not yet used the old values.
		m.Manager.Cache = cfg.Cache
		m.Manager.Client.Key = nil
		mgr.clustered = true
	}
	return mgr, nil
}

// SetLeader marks this node as the ACME issuance leader (or not). In clustered
// mode only the leader orders certs; followers serve from the shared cache. Wired
// to a leader-election coordinator's OnElected/OnLost. No-op meaning in single-node
// mode (the gate is skipped there).
func (m *Manager) SetLeader(v bool) { m.isLeader.Store(v) }

// servingConfig builds a *tls.Config for serving traffic that also answers
// tls-alpn-01 challenges. withHTTP2 adds the h2/http1.1 protos (for the HTTPS
// listener); mail listeners pass false. In clustered mode a NON-leader serves only
// certs already in the shared cache and never triggers issuance — so a client
// hitting a follower for an un-issued host gets unrecognized_name rather than the
// follower racing the leader to order. tls-alpn-01 token requests are always served
// (from the shared cache) on every node, so any node's :443 can answer a validation
// the leader started.
func (m *Manager) servingConfig(withHTTP2 bool) *tls.Config {
	cfg := m.m.TLSConfig(m.fallback, true, true)
	inner := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// tls-alpn-01 challenge: served from cache/in-memory token map, never orders.
		// Allow on every node so a follower's :443 can answer the leader's challenge.
		if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == xacme.ALPNProto {
			return inner(hello)
		}
		// Follower (clustered, not leader): serve-only. Probe the cache; if there is
		// no usable cert, return (nil, nil) — a TLS unrecognized_name alert — instead
		// of letting autocert order (which would race the leader / duplicate accounts).
		if m.clustered && !m.isLeader.Load() {
			host := dns.Domain{ASCII: strings.TrimSuffix(hello.ServerName, ".")}
			if ok, err := m.m.CertAvailable(hello.Context(), m.log, host); err != nil || !ok {
				return nil, nil
			}
		}
		return inner(hello) // leader may order on a cache miss; follower cache-hit serves
	}
	protos := []string{xacme.ALPNProto}
	if withHTTP2 {
		protos = []string{"h2", "http/1.1", xacme.ALPNProto}
	}
	cfg.NextProtos = protos
	return cfg
}

// HTTPSTLSConfig is the serving config for the HTTPS (JMAP/webmail) listener on
// :443 — it advertises h2/http1.1 AND acme-tls/1, so the same listener serves web
// traffic and answers tls-alpn-01. This listener MUST be reachable on :443 for
// issuance to complete.
func (m *Manager) HTTPSTLSConfig() *tls.Config { return m.servingConfig(true) }

// MailTLSConfig is the serving config for the IMAP/submission TLS listeners
// (implicit TLS / STARTTLS). It advertises acme-tls/1 too (harmless for mail
// clients), so those listeners present ACME-managed certs.
func (m *Manager) MailTLSConfig() *tls.Config { return m.servingConfig(false) }

// TLSConfig returns a serving *tls.Config. Retained for single-node callers/tests;
// in clustered mode prefer HTTPSTLSConfig/MailTLSConfig. Equivalent to the mail
// config (no h2), now including the acme-tls/1 responder proto.
func (m *Manager) TLSConfig() *tls.Config { return m.servingConfig(false) }

// EnsureCert proactively obtains (or renews) the certificate for host, so the
// leader issues ahead of client traffic and re-establishes autocert's in-memory
// renew timers after a restart. Uses the RAW autocert GetCertificate — NOT the
// autotls logging wrapper, which dereferences hello.Conn and would panic on this
// synthetic ClientHelloInfo. Call only on the leader (the coordinator's Tick).
func (m *Manager) EnsureCert(host dns.Domain) error {
	_, err := m.m.Manager.GetCertificate(&tls.ClientHelloInfo{ServerName: host.ASCII})
	return err
}

// ACMEChallengeTLSConfig returns the TLS config that answers ACME tls-alpn-01
// challenges on port 443; serve it there so issuance can complete. (The serving
// configs above already answer tls-alpn-01 via their acme-tls/1 NextProto, so this
// is only needed for a dedicated challenge-only listener.)
func (m *Manager) ACMEChallengeTLSConfig() *tls.Config {
	return m.m.ACMETLSConfig
}

// SetACMEHTTPClient overrides the HTTP client the ACME account uses to reach the
// directory. Used by the pebble integration test to trust pebble's self-signed
// ACME directory; production leaves the default (system trust for Let's Encrypt).
func (m *Manager) SetACMEHTTPClient(hc *http.Client) {
	m.m.Manager.Client.HTTPClient = hc
}
