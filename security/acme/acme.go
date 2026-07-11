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
	"context"
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
	"sync"
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
	// mode): every node serves via the direct cache path and issuance is confined to
	// the leader's coordinator Tick. isLeader records leadership (set by the
	// coordinator) — issuance (EnsureCert) is only invoked while leader; the serving
	// path no longer consults it (all clustered nodes direct-serve).
	clustered bool
	isLeader  atomic.Bool
	// leaderMu guards the per-leadership context. leaderCtx is live while this node
	// is leader and cancelled on step-down (SetLeader(false)); EnsureCert threads it
	// so an in-flight order is abandoned when leadership is lost.
	leaderMu     sync.Mutex
	leaderCtx    context.Context
	leaderCancel context.CancelFunc
	// cache is the shared autocert.Cache (nil in single-node mode). Every clustered
	// node reads certs DIRECTLY from it (serveCachedCert) rather than via autocert's
	// GetCertificate — because autocert's cert() arms a background renewal timer on
	// any serve, which would later order a renewal off-leader, defeating
	// leader-gating. Direct serving never touches autocert's renewer.
	cache autocert.Cache
	// certMem is a small in-memory cache of parsed serving certs (keyed by autocert
	// cache key), so the hot TLS path doesn't do a Postgres query + X.509 parse on
	// every ClientHello. Entries are re-validated for expiry on read and refreshed
	// from the shared cache after memTTL, so a brief DB blip doesn't stop serving a
	// recently-served cert. sync.Map: read-mostly, per-key.
	certMem sync.Map // cacheKey(string) → *memCert
}

// memCert is an in-memory cached serving certificate plus the time it was loaded
// from the shared cache (for TTL-based refresh).
type memCert struct {
	cert     *tls.Certificate
	loadedAt time.Time
}

// memTTL bounds how long a parsed cert is served from memory before it is
// refreshed from the shared cache — short enough that a leader renewal propagates
// promptly, long enough to keep the DB off the hot path.
const memTTL = 60 * time.Second

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

// SetLeader marks this node as the ACME issuance leader (or not), wired to a
// leader-election coordinator's OnElected/OnLost. In clustered mode only the leader
// orders certs; followers serve from the shared cache. Beyond the atomic flag it
// manages a per-LEADERSHIP context: becoming leader creates a fresh leaderCtx;
// losing leadership cancels it, so any in-flight EnsureCert order is abandoned
// promptly rather than continuing to completion (and possibly writing to the shared
// cache) after a new leader has taken over — closing the stale-leader double-order
// window that a pre-launch boolean check alone leaves open.
func (m *Manager) SetLeader(v bool) {
	m.leaderMu.Lock()
	defer m.leaderMu.Unlock()
	if v == m.isLeader.Load() {
		return // no transition
	}
	if v {
		m.leaderCtx, m.leaderCancel = context.WithCancel(context.Background())
	} else if m.leaderCancel != nil {
		m.leaderCancel()
		m.leaderCtx, m.leaderCancel = nil, nil
	}
	m.isLeader.Store(v)
}

// leadershipContext returns the current per-leadership context (cancelled on
// step-down), or nil when not leader.
func (m *Manager) leadershipContext() context.Context {
	m.leaderMu.Lock()
	defer m.leaderMu.Unlock()
	return m.leaderCtx
}

// servingConfig builds a *tls.Config for serving traffic. protos sets NextProtos:
// the HTTPS listener passes h2/http1.1/acme-tls/1 (so the same :443 door serves web
// traffic AND answers tls-alpn-01); mail listeners pass nil (empty NextProtos) —
// they never receive a tls-alpn-01 challenge (that only lands on :443), and
// advertising ONLY acme-tls/1 would break an IMAP/submission client that offers its
// own ALPN with no overlap (Go fails the handshake on non-overlapping ALPN).
//
// In CLUSTERED mode EVERY node (leader included) serves via the direct cache path
// (serveCachedCert), NOT autocert's GetCertificate. autocert's cert() arms a
// background renewal timer on any serve, and such a timer survives a
// demotion-without-exit and would later order off-leader — so keeping issuance off
// the serving path entirely is what makes "only the leader orders" hold. Issuance +
// renewal happen ONLY in the leader's coordinator Tick (EnsureCert). Single-node
// (non-clustered) mode has no coordinator, so it still serves via autocert (which
// issues lazily on a cache miss) — the legacy behavior. tls-alpn-01 token requests
// always go through autocert (served from the shared cache, never order) so any
// node's :443 can answer a validation the leader started.
func (m *Manager) servingConfig(protos []string) *tls.Config {
	cfg := m.m.TLSConfig(m.fallback, true, true)
	inner := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// tls-alpn-01 challenge: served from cache/in-memory token map, never orders.
		// Goes through autocert on every node so a :443 can answer the leader's challenge.
		if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == xacme.ALPNProto {
			return inner(hello)
		}
		// Clustered: serve DIRECTLY from the shared cache on every node (leader and
		// follower alike), never arming autocert's renewer. A miss returns (nil, nil)
		// → TLS unrecognized_name; issuance is the leader Tick's job, not the serving
		// path's.
		if m.clustered {
			return m.serveCachedCert(hello)
		}
		return inner(hello) // single-node: autocert issues lazily on a cache miss
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
		if cert := m.lookupCert(ctx, k); cert != nil {
			return cert, nil
		}
	}
	return nil, nil
}

// lookupCert returns a currently-valid serving cert for cache key k, from the
// in-memory cache when fresh, else from the shared cache (parsed and memoized).
// Returns nil on miss / unusable / expired. Keeps the Postgres query + X.509 parse
// off the hot TLS path except on a cold miss or after memTTL.
func (m *Manager) lookupCert(ctx context.Context, k string) *tls.Certificate {
	now := timeNow()
	if v, ok := m.certMem.Load(k); ok {
		mc := v.(*memCert)
		// Serve from memory while fresh AND still within cert validity.
		if now.Sub(mc.loadedAt) < memTTL && certValid(mc.cert, now) {
			return mc.cert
		}
	}
	data, err := m.cache.Get(ctx, k)
	if err != nil {
		if !errors.Is(err, autocert.ErrCacheMiss) {
			// A transient cache (DB) error would otherwise be a silent TLS outage
			// (fail-closed → unrecognized_name); log it distinctly from a real miss.
			// Fall back to a still-valid in-memory entry if we have one, so a brief DB
			// blip doesn't stop serving a recently-served cert.
			m.log.Errorx("acme: reading cached certificate", err, slog.String("cachekey", k))
			if v, ok := m.certMem.Load(k); ok {
				if mc := v.(*memCert); certValid(mc.cert, now) {
					return mc.cert
				}
			}
		} else {
			m.certMem.Delete(k) // definitively gone from shared storage
		}
		return nil
	}
	cert, ok := parseCachedKeycert(data)
	if !ok || !certValid(cert, now) {
		return nil
	}
	m.certMem.Store(k, &memCert{cert: cert, loadedAt: now})
	return cert
}

// certValid reports whether cert is currently within its validity window.
func certValid(cert *tls.Certificate, now time.Time) bool {
	return cert != nil && cert.Leaf != nil && !now.Before(cert.Leaf.NotBefore) && !now.After(cert.Leaf.NotAfter)
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

// EnsureCert proactively obtains (or renews) the certificate for host — the ONLY
// issuance path in clustered mode (the serving path never orders). It warms BOTH
// the ECDSA and RSA variants: a synthetic hello with no cipher/curve info makes
// autocert pick RSA, but real clients overwhelmingly negotiate ECDSA — and the
// serve path looks up the ECDSA key first — so warming only RSA would leave the
// cert clients actually use unissued. Uses the RAW autocert GetCertificate — NOT
// the autotls logging wrapper, which dereferences hello.Conn and would panic on a
// synthetic ClientHelloInfo. Call only on the leader (the coordinator's Tick).
//
// autocert's GetCertificate runs on its own internal context, so to honor
// cancellation the two orders run in a goroutine and EnsureCert returns as soon as
// EITHER the caller's ctx (bound to the tick — cancelled on shutdown) OR the
// per-leadership context (cancelled on step-down) is done. So a stuck order can't
// stall subsequent ticks or delay shutdown, and — critically — an order in flight
// when leadership is lost is abandoned rather than running to completion off-leader.
// (The background goroutine itself is bounded by autocert's own 5-minute deadline;
// abandoning it just means we stop waiting and never treat its result as ours.)
func (m *Manager) EnsureCert(ctx context.Context, host dns.Domain) error {
	// Defense in depth: EnsureCert is the ONLY path that orders, so refuse to run it
	// unless this node is the leader — a stray/racing call on a non-leader (or after
	// step-down) can never order off-leader. The coordinator only invokes it from the
	// leader Tick anyway; this makes the invariant local to the ordering primitive.
	if m.clustered && !m.isLeader.Load() {
		return nil
	}
	leaderCtx := m.leadershipContext() // nil in single-node mode
	done := make(chan error, 1)
	go func() {
		// ECDSA variant: advertise ECDSA capability so supportsECDSA() is true.
		ecdsaHello := &tls.ClientHelloInfo{
			ServerName:       host.ASCII,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}
		if _, err := m.m.Manager.GetCertificate(ecdsaHello); err != nil {
			done <- err
			return
		}
		// RSA variant: no ECDSA capability → autocert picks RSA (for legacy clients).
		rsaHello := &tls.ClientHelloInfo{
			ServerName:   host.ASCII,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		}
		_, err := m.m.Manager.GetCertificate(rsaHello)
		done <- err
	}()
	// Wait for completion, caller cancellation, or loss of leadership.
	var leaderDone <-chan struct{}
	if leaderCtx != nil {
		leaderDone = leaderCtx.Done()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-leaderDone:
		return context.Canceled // leadership lost mid-order; abandon it
	}
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
