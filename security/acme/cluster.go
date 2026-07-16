package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/autocert"
	"github.com/mjl-/mox/dns"
	"golang.org/x/crypto/acme"
)

// defaultRenewBefore is how long before expiry a certificate is renewed when
// ClusterConfig.RenewBefore is zero (matches autocert's default).
const defaultRenewBefore = 30 * 24 * time.Hour

// perHostIssueTimeout bounds a single host's DNS-01 order so one stuck
// authorization cannot wedge the leader renewal pass.
const perHostIssueTimeout = 3 * time.Minute

// ClusterConfig configures a ClusterManager.
type ClusterConfig struct {
	Pool         *pgxpool.Pool // shared ACME state store (schema/10_acme_cache.sql)
	DirectoryURL string        // ACME directory (Let's Encrypt prod/staging, or pebble)
	ContactEmail string        // ACME account contact
	Hostnames    []dns.Domain  // hostnames the cluster obtains certificates for
	Solver       DNSSolver     // dns-01 record publisher (webhook in production)
	RenewBefore  time.Duration // renew this long before expiry (0 = 30 days)
	Log          *slog.Logger  // nil = slog.Default()
}

// ClusterManager runs octo-mail's leader-gated, DNS-01, multi-node ACME issuance.
//
// Exactly one node (the elected leader) calls RenewOnce, which orders/renews
// certificates over dns-01 and writes them to the shared Postgres store. EVERY
// node serves TLS via TLSConfig, reading certificates from that shared store and
// NEVER issuing — so leadership is consulted only on the background renewal loop,
// never on the TLS hot path. A per-node refresher (refreshLoop) reloads a
// certificate after the leader renews it, bounded by the poll interval.
type ClusterManager struct {
	cache       *pgCache
	client      *acme.Client
	solver      DNSSolver
	hosts       []string // ASCII hostnames
	contact     string
	renewBefore time.Duration
	log         *slog.Logger
	dirHash     string // sha256(directoryURL) hex — namespaces the account key per directory

	regMu      sync.Mutex
	registered bool // account registered this process (KID cached on the client)

	mu    sync.RWMutex
	certs map[string]*tls.Certificate // host -> served cert
	seen  map[string]time.Time        // host -> updated_at last loaded (refresh marker)
}

// NewCluster builds a ClusterManager. It does not touch the network or the
// account key here: issuance state is established lazily inside RenewOnce (leader
// only), so followers can construct and serve without an account key.
func NewCluster(cfg ClusterConfig) (*ClusterManager, error) {
	if cfg.Pool == nil {
		return nil, fmt.Errorf("acme cluster: nil pool")
	}
	if cfg.DirectoryURL == "" {
		return nil, fmt.Errorf("acme cluster: empty directory URL")
	}
	if cfg.ContactEmail == "" {
		return nil, fmt.Errorf("acme cluster: empty contact email")
	}
	if cfg.Solver == nil {
		return nil, fmt.Errorf("acme cluster: nil DNS solver")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	renew := cfg.RenewBefore
	if renew == 0 {
		renew = defaultRenewBefore
	}
	hosts := make([]string, 0, len(cfg.Hostnames))
	for _, h := range cfg.Hostnames {
		hosts = append(hosts, h.ASCII)
	}
	sum := sha256.Sum256([]byte(cfg.DirectoryURL))
	return &ClusterManager{
		cache:       newPGCache(cfg.Pool),
		client:      &acme.Client{DirectoryURL: cfg.DirectoryURL, UserAgent: "octo-mail"},
		solver:      cfg.Solver,
		hosts:       hosts,
		contact:     cfg.ContactEmail,
		renewBefore: renew,
		log:         log,
		dirHash:     hex.EncodeToString(sum[:]),
		certs:       map[string]*tls.Certificate{},
		seen:        map[string]time.Time{},
	}, nil
}

// SetACMEHTTPClient overrides the HTTP client the ACME account uses to reach the
// directory. Used by the pebble integration test to trust pebble's self-signed
// directory; production leaves the default (system trust for Let's Encrypt). Call
// before the first RenewOnce.
func (m *ClusterManager) SetACMEHTTPClient(hc *http.Client) { m.client.HTTPClient = hc }

func (m *ClusterManager) acctKeyName() string { return "acct-key:" + m.dirHash }
func certName(host string) string             { return "cert:" + host }

// TLSConfig returns a *tls.Config whose GetCertificate serves cluster certificates
// from the shared store. It never issues. Suitable for IMAP/SMTP implicit TLS and
// HTTPS listeners on every node.
func (m *ClusterManager) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.getCertificate}
}

func (m *ClusterManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, nil // no SNI: let the caller's default handling apply
	}
	m.mu.RLock()
	cert := m.certs[host]
	m.mu.RUnlock()
	if cert != nil {
		return cert, nil
	}
	// Cold miss (e.g. before the first refresh tick): one synchronous load.
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cert, _, err := m.loadCert(ctx, host)
	if err != nil {
		// Missing/unparseable cert → "unrecognized name" to the client, not a
		// hard error (matches the legacy manager's unknown-SNI behavior).
		return nil, nil
	}
	return cert, nil
}

// loadCert reads and parses the stored certificate bundle for host. It does not
// cache; callers (getCertificate cold path, refreshLoop) decide caching.
func (m *ClusterManager) loadCert(ctx context.Context, host string) (*tls.Certificate, time.Time, error) {
	data, err := m.cache.Get(ctx, certName(host))
	if err != nil {
		return nil, time.Time{}, err
	}
	// The bundle holds both the PRIVATE KEY and CERTIFICATE blocks; X509KeyPair
	// scans each argument for the block type it needs, so passing the bundle for
	// both cert and key is correct.
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("acme: parse cert bundle for %q: %w", host, err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, time.Time{}, fmt.Errorf("acme: parse leaf for %q: %w", host, err)
		}
		cert.Leaf = leaf
	}
	return &cert, leaf.NotAfter, nil
}

// RefreshOnce reloads any certificate whose shared-store updated_at changed since
// last seen, so a follower picks up the leader's renewals. Returns the number
// reloaded. Safe to call on every node.
func (m *ClusterManager) RefreshOnce(ctx context.Context) int {
	n := 0
	for _, host := range m.hosts {
		ts, ok, err := m.cache.updatedAt(ctx, certName(host))
		if err != nil {
			m.log.WarnContext(ctx, "acme refresh: updated_at failed", "host", host, "err", err)
			continue
		}
		if !ok {
			continue // not issued yet
		}
		m.mu.RLock()
		prev, had := m.seen[host]
		m.mu.RUnlock()
		if had && prev.Equal(ts) {
			continue // unchanged
		}
		cert, _, err := m.loadCert(ctx, host)
		if err != nil {
			m.log.WarnContext(ctx, "acme refresh: load failed", "host", host, "err", err)
			continue
		}
		m.mu.Lock()
		m.certs[host] = cert
		m.seen[host] = ts
		m.mu.Unlock()
		n++
	}
	return n
}

// RunRefresh runs RefreshOnce immediately and then every interval until ctx is
// done. Started on every node so served certificates track the shared store.
func (m *ClusterManager) RunRefresh(ctx context.Context, interval time.Duration) {
	m.RefreshOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.RefreshOnce(ctx)
		}
	}
}

// RenewOnce is the leader's issuance/renewal pass: it obtains a certificate for
// every managed host that is missing or within RenewBefore of expiry. Call ONLY
// from the leader (e.g. an ops/ha.Coordinator Tick). Per-host errors are logged
// and do not abort the remaining hosts.
func (m *ClusterManager) RenewOnce(ctx context.Context) {
	if err := m.ensureRegistered(ctx); err != nil {
		m.log.WarnContext(ctx, "acme: account registration failed", "err", err)
		return
	}
	for _, host := range m.hosts {
		if !m.needsRenewal(ctx, host) {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, perHostIssueTimeout)
		err := m.issue(hctx, host)
		cancel()
		if err != nil {
			m.log.WarnContext(ctx, "acme: issuance failed", "host", host, "err", err)
			continue
		}
		m.log.InfoContext(ctx, "acme: certificate issued", "host", host)
	}
}

// needsRenewal reports whether host has no stored cert or one within renewBefore
// of expiry. A load error is treated as "needs renewal" so a corrupt bundle is
// reissued rather than stranding the host.
func (m *ClusterManager) needsRenewal(ctx context.Context, host string) bool {
	_, notAfter, err := m.loadCert(ctx, host)
	if err != nil {
		return true
	}
	return time.Until(notAfter) < m.renewBefore
}

// ensureRegistered loads (or, first time, generates and stores) the shared ACME
// account key, sets it on the client, and registers the account. Registration is
// idempotent: x/crypto caches the account KID even when the key is already
// registered (ErrAccountAlreadyExists), which we treat as success.
func (m *ClusterManager) ensureRegistered(ctx context.Context) error {
	m.regMu.Lock()
	defer m.regMu.Unlock()
	if m.registered {
		return nil
	}
	key, err := m.loadOrCreateAccountKey(ctx)
	if err != nil {
		return err
	}
	m.client.Key = key
	acct := &acme.Account{Contact: []string{"mailto:" + m.contact}}
	if _, err := m.client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("acme: register account: %w", err)
	}
	m.registered = true
	return nil
}

// loadOrCreateAccountKey returns the shared account key, generating and persisting
// a fresh ECDSA P-256 key on first use so the whole cluster registers ONE account.
func (m *ClusterManager) loadOrCreateAccountKey(ctx context.Context) (crypto.Signer, error) {
	data, err := m.cache.Get(ctx, m.acctKeyName())
	switch {
	case err == nil:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("acme: account key: no PEM data")
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme: parse account key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("acme: account key is not a signer (%T)", k)
		}
		return signer, nil
	case !errors.Is(err, autocert.ErrCacheMiss):
		// Any error other than a cache miss is a real failure.
		return nil, err
	}
	// Cache miss: generate and persist a fresh account key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("acme: generate account key: %w", err)
	}
	pemBytes, err := marshalKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := m.cache.Put(ctx, m.acctKeyName(), pemBytes); err != nil {
		return nil, err
	}
	return key, nil
}

// issue runs the full dns-01 order flow for one host and stores the resulting
// certificate bundle in the shared store.
func (m *ClusterManager) issue(ctx context.Context, host string) error {
	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := m.solveAuthz(ctx, authzURL); err != nil {
			return err
		}
	}
	// All authorizations satisfied: finalize with a fresh per-cert key.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cert key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, certKey)
	if err != nil {
		return fmt.Errorf("create csr: %w", err)
	}
	der, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}
	bundle, err := encodeBundle(certKey, der)
	if err != nil {
		return err
	}
	if err := m.cache.Put(ctx, certName(host), bundle); err != nil {
		return err
	}
	return nil
}

// solveAuthz fulfills one authorization via its dns-01 challenge.
func (m *ClusterManager) solveAuthz(ctx context.Context, authzURL string) error {
	authz, err := m.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil // already authorized (reused)
	}
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("no dns-01 challenge for %q", authz.Identifier.Value)
	}
	rec, err := m.client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("dns-01 record: %w", err)
	}
	fqdn := "_acme-challenge." + authz.Identifier.Value
	if err := m.solver.Present(ctx, fqdn, rec); err != nil {
		return fmt.Errorf("present dns-01: %w", err)
	}
	defer func() {
		if err := m.solver.CleanUp(context.WithoutCancel(ctx), fqdn, rec); err != nil {
			m.log.WarnContext(ctx, "acme: dns-01 cleanup failed", "fqdn", fqdn, "err", err)
		}
	}()
	if _, err := m.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept dns-01: %w", err)
	}
	if _, err := m.client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("wait authorization for %q: %w", authz.Identifier.Value, err)
	}
	return nil
}

// marshalKeyPEM PKCS#8-encodes an ECDSA key as a PEM PRIVATE KEY block.
func marshalKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("acme: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// encodeBundle produces the stored cert bundle: the private key PEM block
// followed by the CERTIFICATE chain (leaf first). tls.X509KeyPair(bundle, bundle)
// reconstructs the tls.Certificate.
func encodeBundle(key crypto.Signer, chain [][]byte) ([]byte, error) {
	keyPEM, err := marshalKeyPEM(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), keyPEM...)
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, nil
}
