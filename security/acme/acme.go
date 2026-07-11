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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/mjl-/autocert"
	"github.com/mjl-/mox/autotls"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

// timeNow is overridable in tests; defaults to time.Now.
var timeNow = time.Now

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
	// cache is the shared autocert.Cache (nil in single-node mode). A follower reads
	// certs DIRECTLY from it (serveCachedCert) rather than via autocert's
	// GetCertificate — because autocert's cert() arms a background renewal timer on
	// every cache-hit, which would later order a renewal ON THE FOLLOWER, defeating
	// leader-gating. Direct serving never touches autocert's renewer.
	cache autocert.Cache
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
		mgr.cache = cfg.Cache
	}
	return mgr, nil
}

// SetLeader marks this node as the ACME issuance leader (or not). In clustered
// mode only the leader orders certs; followers serve from the shared cache. Wired
// to a leader-election coordinator's OnElected/OnLost. No-op meaning in single-node
// mode (the gate is skipped there).
func (m *Manager) SetLeader(v bool) { m.isLeader.Store(v) }

// servingConfig builds a *tls.Config for serving traffic. protos sets NextProtos:
// the HTTPS listener passes h2/http1.1/acme-tls/1 (so the same :443 door serves web
// traffic AND answers tls-alpn-01); mail listeners pass nil (empty NextProtos) —
// they never receive a tls-alpn-01 challenge (that only lands on :443), and
// advertising ONLY acme-tls/1 would break an IMAP/submission client that offers its
// own ALPN with no overlap (Go fails the handshake on non-overlapping ALPN). In
// clustered mode a NON-leader serves only certs already in the shared cache and
// never triggers issuance — a client hitting a follower for an un-issued host gets
// unrecognized_name rather than the follower racing the leader to order. tls-alpn-01
// token requests are always served (from the shared cache) on every node, so any
// node's :443 can answer a validation the leader started.
func (m *Manager) servingConfig(protos []string) *tls.Config {
	cfg := m.m.TLSConfig(m.fallback, true, true)
	inner := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// tls-alpn-01 challenge: served from cache/in-memory token map, never orders.
		// Allow on every node so a follower's :443 can answer the leader's challenge.
		if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == xacme.ALPNProto {
			return inner(hello)
		}
		// Follower (clustered, not leader): serve-only, DIRECTLY from the shared
		// cache. We must NOT delegate to autocert's GetCertificate even on a cache
		// hit: autocert.cert() arms a background renewal timer on every hit, which
		// would later order a renewal on this follower (off-leader), reintroducing
		// the H17 multi-node ordering race for the steady-state renewal case. Direct
		// serving returns the cached cert without touching autocert's renewer; a miss
		// returns (nil, nil) → TLS unrecognized_name (no order).
		if m.clustered && !m.isLeader.Load() {
			return m.serveCachedCert(hello)
		}
		return inner(hello) // leader may order on a cache miss; single-node always issues
	}
	cfg.NextProtos = protos
	return cfg
}

// HTTPSTLSConfig is the serving config for the HTTPS (JMAP/webmail) listener on
// :443 — it advertises h2/http1.1 AND acme-tls/1, so the same listener serves web
// traffic and answers tls-alpn-01. This listener MUST be reachable on :443 for
// issuance to complete.
func (m *Manager) HTTPSTLSConfig() *tls.Config {
	return m.servingConfig([]string{"h2", "http/1.1", xacme.ALPNProto})
}

// MailTLSConfig is the serving config for the IMAP/submission TLS listeners
// (implicit TLS / STARTTLS). It sets NO NextProtos: mail listeners never receive a
// tls-alpn-01 challenge (that lands only on :443), and advertising only acme-tls/1
// would break a mail client that offers a non-overlapping ALPN. Certs are still
// ACME-managed via GetCertificate.
func (m *Manager) MailTLSConfig() *tls.Config { return m.servingConfig(nil) }

// TLSConfig returns a serving *tls.Config with no forced ALPN. Retained for
// single-node callers/tests; in clustered mode prefer HTTPSTLSConfig/MailTLSConfig.
func (m *Manager) TLSConfig() *tls.Config { return m.servingConfig(nil) }

// serveCachedCert returns the cached certificate for hello's SNI, read DIRECTLY
// from the shared cache (no autocert state, no renewal timer). It mirrors autotls's
// serving fallback (fallbackNoSNI + fallbackUnknownSNI, both enabled for our
// listeners): an empty, IP-literal, dotless, or non-allowlisted SNI is served the
// fallback host's cert — so a legitimate mail client that sends a bare domain
// instead of the MX hostname gets the same cert on a follower as it would on the
// leader (not an unrecognized_name). It picks the ECDSA or RSA variant by client
// capability. A genuine cache miss / unusable / expired cert returns (nil, nil) — a
// TLS unrecognized_name alert. Used only on a follower; the leader/single-node path
// goes through autocert. Never orders.
func (m *Manager) serveCachedCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.cache == nil {
		return nil, nil
	}
	ctx := hello.Context()
	name := strings.TrimSuffix(hello.ServerName, ".")
	// Resolve the effective host, mirroring autotls's fallback decisions:
	//   - IP-literal SNI, empty SNI, or a dotless name → fallback host
	//   - a well-formed name that is NOT allowlisted → fallback host
	// (Our servingConfig builds the autotls config with fallbackNoSNI +
	// fallbackUnknownSNI both true, so the leader path serves the fallback here too.)
	if name == "" || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		name = m.fallback.ASCII
	} else if m.m.HostPolicy(ctx, name) != nil {
		// Not an allowlisted host (or shutting down) → fallback, like the leader.
		name = m.fallback.ASCII
	}
	if name == "" {
		return nil, nil
	}
	// Prefer ECDSA; fall back to the "+rsa" variant for legacy clients. Try the
	// client-preferred type first, then the other, so we serve whatever is cached.
	keys := []string{name, name + "+rsa"}
	if !supportsECDSA(hello) {
		keys = []string{name + "+rsa", name}
	}
	for _, k := range keys {
		data, err := m.cache.Get(ctx, k)
		if err != nil {
			if !errors.Is(err, autocert.ErrCacheMiss) {
				// A transient cache (DB) error is fail-closed here (we serve no cert →
				// unrecognized_name), but that turns a DB blip into a silent TLS outage,
				// so make it visible rather than indistinguishable from a real miss.
				m.log.Errorx("acme: reading cached certificate on follower", err, slog.String("cachekey", k))
			}
			continue // miss or transient — try the other variant
		}
		cert, ok := parseCachedKeycert(data)
		if !ok {
			continue
		}
		// Serve only a currently-valid cert (the leader renews before expiry).
		if now := timeNow(); cert.Leaf != nil && (now.Before(cert.Leaf.NotBefore) || now.After(cert.Leaf.NotAfter)) {
			continue
		}
		return cert, nil
	}
	return nil, nil
}

// parseCachedKeycert decodes autocert's cached keycert blob (PEM private key
// followed by one or more PEM certificates) into a usable *tls.Certificate with a
// parsed Leaf. Returns ok=false on any malformation.
func parseCachedKeycert(data []byte) (*tls.Certificate, bool) {
	priv, rest := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, false
	}
	key, err := parsePrivateKey(priv.Bytes)
	if err != nil {
		return nil, false
	}
	var chain [][]byte
	for len(rest) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			chain = append(chain, b.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, false
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, true
}

// EnsureCert proactively obtains (or renews) the certificate for host, so the
// leader issues ahead of client traffic and re-establishes autocert's in-memory
// renew timers after a restart. It warms BOTH the ECDSA and RSA variants: a
// synthetic hello with no cipher/curve info makes autocert pick RSA, but real
// clients overwhelmingly negotiate ECDSA — and the follower serve path looks up the
// ECDSA key first — so warming only RSA would leave the cert clients actually use
// unissued. Uses the RAW autocert GetCertificate — NOT the autotls logging wrapper,
// which dereferences hello.Conn and would panic on a synthetic ClientHelloInfo.
// Call only on the leader (the coordinator's Tick).
func (m *Manager) EnsureCert(host dns.Domain) error {
	// ECDSA variant: advertise ECDSA capability so supportsECDSA() is true.
	ecdsaHello := &tls.ClientHelloInfo{
		ServerName:       host.ASCII,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	if _, err := m.m.Manager.GetCertificate(ecdsaHello); err != nil {
		return err
	}
	// RSA variant: no ECDSA capability → autocert picks RSA (for legacy clients).
	rsaHello := &tls.ClientHelloInfo{
		ServerName:   host.ASCII,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	_, err := m.m.Manager.GetCertificate(rsaHello)
	return err
}

// ACMEChallengeTLSConfig returns the TLS config that answers ACME tls-alpn-01
// challenges on port 443; serve it there so issuance can complete. (The serving
// configs above already answer tls-alpn-01 via their acme-tls/1 NextProto, so this
// is only needed for a dedicated challenge-only listener.)
func (m *Manager) ACMEChallengeTLSConfig() *tls.Config {
	return m.m.ACMETLSConfig
}

// supportsECDSA reports whether the client can use an ECDSA certificate — a
// verbatim port of autocert's unexported helper (we need the same decision on the
// direct follower serve path to pick the ECDSA vs RSA cached variant).
func supportsECDSA(hello *tls.ClientHelloInfo) bool {
	if hello.SignatureSchemes != nil {
		ecdsaOK := false
	schemeLoop:
		for _, scheme := range hello.SignatureSchemes {
			const tlsECDSAWithSHA1 tls.SignatureScheme = 0x0203
			switch scheme {
			case tlsECDSAWithSHA1, tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ecdsaOK = true
				break schemeLoop
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		ecdsaOK := false
		for _, curve := range hello.SupportedCurves {
			if curve == tls.CurveP256 {
				ecdsaOK = true
				break
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}

// parsePrivateKey parses a DER private key (PKCS#1, PKCS#8, or SEC1 EC) — a
// verbatim port of autocert's unexported helper, for the direct follower serve.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme: unknown PKCS#8 private key type")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("acme: failed to parse private key")
}

// SetACMEHTTPClient overrides the HTTP client the ACME account uses to reach the
// directory. Used by the pebble integration test to trust pebble's self-signed
// ACME directory; production leaves the default (system trust for Let's Encrypt).
func (m *Manager) SetACMEHTTPClient(hc *http.Client) {
	m.m.Manager.Client.HTTPClient = hc
}
