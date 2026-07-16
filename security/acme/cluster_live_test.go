package acme_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/security/acme"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dns"
)

// challtestsrvSolver drives pebble-challtestsrv's management API to publish/clear
// the _acme-challenge TXT record for a dns-01 challenge. Test-only: production
// uses the webhook solver. Default mgmt endpoint http://localhost:8055 (override
// with OCTO_MAIL_ACME_CHALLTESTSRV).
type challtestsrvSolver struct {
	base string
	hc   *http.Client
}

func (s *challtestsrvSolver) post(ctx context.Context, path string, body map[string]string) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("challtestsrv %s: status %d", path, resp.StatusCode)
	}
	return nil
}

// challtestsrv keys TXT records by FQDN with a trailing dot.
func (s *challtestsrvSolver) Present(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, "/set-txt", map[string]string{"host": fqdn + ".", "value": value})
}
func (s *challtestsrvSolver) CleanUp(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, "/clear-txt", map[string]string{"host": fqdn + "."})
}

// TestACMEClusterDNSIssuance exercises the leader-gated ClusterManager against a
// real pebble CA over dns-01, with the shared Postgres store backing the manager.
// Integration counterpart to the offline cluster tests; proves the #32 path end to
// end: RenewOnce registers the account, orders, publishes the TXT via challtestsrv,
// finalizes, and stores a servable certificate — then is idempotent on a fresh cert.
//
// Gated by OCTO_MAIL_ACME=1. Provision:
//
//	scripts/acme-pebble.sh up      # pebble (:14000) + challtestsrv DNS (:8053) + mgmt (:8055)
//	# plus Postgres 17 at OCTO_MAIL_DSN / localhost:55432
//	OCTO_MAIL_ACME=1 OCTO_MAIL_ACME_CA=/tmp/octo-mail-pebble-minica.pem \
//	  go test -run TestACMEClusterDNSIssuance ./security/acme/
func TestACMEClusterDNSIssuance(t *testing.T) {
	if os.Getenv("OCTO_MAIL_ACME") != "1" {
		t.Skip("cluster DNS-01 test requires OCTO_MAIL_ACME=1, pebble + challtestsrv (scripts/acme-pebble.sh up), and Postgres")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	dsn := os.Getenv("OCTO_MAIL_DSN")
	if dsn == "" {
		dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	// Ensure the shared table exists (mirrors schema/10_acme_cache.sql) and start clean.
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS acme_cache (name text PRIMARY KEY, data bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE acme_cache`); err != nil {
		t.Fatal(err)
	}

	caPath := os.Getenv("OCTO_MAIL_ACME_CA")
	if caPath == "" {
		caPath = "/tmp/octo-mail-pebble-minica.pem"
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read pebble minica (%s): %v", caPath, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatalf("minica PEM not parsed")
	}
	acmeHTTP := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
		Timeout:   30 * time.Second,
	}

	challBase := os.Getenv("OCTO_MAIL_ACME_CHALLTESTSRV")
	if challBase == "" {
		challBase = "http://localhost:8055"
	}
	const host = "mail.octo-mail.test"
	cm, err := acme.NewCluster(acme.ClusterConfig{
		Pool:         pool,
		DirectoryURL: "https://localhost:14000/dir",
		ContactEmail: "admin@localhost",
		Hostnames:    []dns.Domain{{ASCII: host}},
		Solver:       &challtestsrvSolver{base: challBase, hc: &http.Client{Timeout: 10 * time.Second}},
	})
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	cm.SetACMEHTTPClient(acmeHTTP)

	// Leader issuance pass, then verify a servable cert landed in the shared store.
	cm.RenewOnce(ctx)
	if n := cm.RefreshOnce(ctx); n != 1 {
		t.Fatalf("expected 1 cert stored+loaded after RenewOnce, got %d", n)
	}
	cert, err := cm.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || cert == nil || cert.Leaf == nil {
		t.Fatalf("no servable cert after issuance: cert=%v err=%v", cert, err)
	}
	pebbleRoots := fetchPebbleRoots(t, acmeHTTP)
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if c, e := x509.ParseCertificate(der); e == nil {
			inter.AddCert(c)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pebbleRoots, Intermediates: inter}); err != nil {
		t.Fatalf("issued cert does not verify for %s: %v", host, err)
	}
	t.Logf("OK: cluster DNS-01 issuance via pebble — leaf SAN %s, notAfter=%s", host, cert.Leaf.NotAfter.Format(time.RFC3339))

	// Idempotence: a second pass with a fresh cert must not reissue (updated_at stable).
	before := pgUpdatedAt(t, ctx, pool, "cert:"+host)
	cm.RenewOnce(ctx)
	after := pgUpdatedAt(t, ctx, pool, "cert:"+host)
	if !before.Equal(after) {
		t.Fatalf("RenewOnce reissued a fresh cert (updated_at %v -> %v)", before, after)
	}
}

func pgUpdatedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) time.Time {
	t.Helper()
	var ts time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM acme_cache WHERE name=$1`, name).Scan(&ts); err != nil {
		t.Fatalf("read %s updated_at: %v", name, err)
	}
	return ts
}
