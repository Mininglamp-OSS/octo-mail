package acme_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/security/acme"
	"github.com/mjl-/mox/dns"
)

// TestACMELiveIssuance exercises octo-mail's acme.Manager against a REAL ACME CA
// (a local pebble server) over the tls-alpn-01 challenge. It is the integration
// counterpart to the offline TestACMEManagerWiring.
//
// What it proves against a real CA (verified in pebble's logs): octo-mail's manager
// performs ACME account registration, order creation, serves the tls-alpn-01
// challenge from ACMEChallengeTLSConfig, the CA marks the authorization VALID,
// and the CA issues the certificate.
//
// Honest boundary: with pebble v2.10 + the vendored golang.org/x/crypto/acme
// v0.51, the post-finalize certificate *retrieval* (CreateOrderCert → WaitOrder)
// can fail because pebble's finalize response omits the order URI in the body
// that x/crypto expects, so the client cannot always download the just-issued
// cert. That is a CA-emulator/library interaction, not a octo-mail wiring defect
// (the CA logs show issuance succeeding). Production Let's Encrypt returns a
// spec-compliant finalize response. This test is therefore gated behind
// OCTO_MAIL_ACME=1 and left as a reproducible harness rather than a gating check.
//
// Provision with:
//
//	scripts/acme-pebble.sh up
//	OCTO_MAIL_ACME=1 OCTO_MAIL_ACME_CA=/tmp/octo-mail-pebble-minica.pem \
//	OCTO_MAIL_ACME_HOST_IP=<host-lan-ip> \
//	  go test -run TestACMELiveIssuance ./security/acme/
func TestACMELiveIssuance(t *testing.T) {
	if os.Getenv("OCTO_MAIL_ACME") != "1" {
		t.Skip("ACME live-issuance test requires OCTO_MAIL_ACME=1 and a pebble server (scripts/acme-pebble.sh up)")
	}
	caPath := os.Getenv("OCTO_MAIL_ACME_CA")
	if caPath == "" {
		caPath = "/tmp/octo-mail-pebble-minica.pem"
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read pebble minica (%s): %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("minica PEM not parsed")
	}

	// The ACME account talks to pebble's HTTPS directory, which is signed by the
	// minica — trust it via a custom HTTP client.
	acmeHTTP := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   30 * time.Second,
	}

	mgr, err := acme.New(acme.Config{
		CacheDir:     t.TempDir(),
		ContactEmail: "admin@localhost",
		DirectoryURL: "https://localhost:14000/dir",
		Hostnames:    []dns.Domain{{ASCII: "mail.octo-mail.test"}},
		Fallback:     dns.Domain{ASCII: "mail.octo-mail.test"},
	})
	if err != nil {
		t.Fatalf("acme.New: %v", err)
	}
	mgr.SetACMEHTTPClient(acmeHTTP)

	// Serve the tls-alpn-01 challenge on :5001 — pebble's default TLS-ALPN-01
	// validation port. Bind all interfaces so pebble (in the Docker VM on macOS)
	// can reach it via the host LAN IP that challtestsrv resolves the domain to.
	chLn, err := tls.Listen("tcp", ":5001", mgr.ACMEChallengeTLSConfig())
	if err != nil {
		t.Fatalf("listen 5001 (challenge): %v", err)
	}
	defer chLn.Close()
	go acceptHandshakes(chLn)

	// Serve normal TLS with the manager's production config on an ephemeral port;
	// a real handshake here drives the full ACME order (new-account → new-order →
	// tls-alpn-01 authz → finalize) and yields the issued certificate.
	srvLn, err := tls.Listen("tcp", "127.0.0.1:0", mgr.TLSConfig())
	if err != nil {
		t.Fatalf("listen (serving): %v", err)
	}
	defer srvLn.Close()
	go acceptHandshakes(srvLn)

	// Give the challenge listener a moment to be ready before triggering issuance,
	// so autocert's first order sees a working tls-alpn-01 responder and does not
	// cache a failed order state (~60s TTL) that would stall later attempts.
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	var leaf *x509.Certificate
	var chain [][]byte
	deadline := time.Now().Add(180 * time.Second)
	for {
		// Each handshake blocks server-side while autocert runs the full ACME order
		// under the (long-lived) server handshake context. On an early miss we wait
		// past autocert's ~60s failed-state TTL before retrying rather than
		// hammering (which would keep re-hitting the cached failed state).
		d := tls.Dialer{Config: &tls.Config{ServerName: "mail.octo-mail.test", InsecureSkipVerify: true}}
		dctx, dcancel := context.WithTimeout(ctx, 45*time.Second)
		conn, derr := d.DialContext(dctx, "tcp", srvLn.Addr().String())
		if derr == nil {
			cs := conn.(*tls.Conn).ConnectionState()
			_ = conn.Close()
			if len(cs.PeerCertificates) > 0 {
				leaf = cs.PeerCertificates[0]
				for _, c := range cs.PeerCertificates {
					chain = append(chain, c.Raw)
				}
				dcancel()
				break
			}
		}
		dcancel()
		if time.Now().After(deadline) {
			t.Fatalf("issuance did not complete in time: %v", derr)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context: %v", ctx.Err())
		case <-time.After(20 * time.Second):
		}
	}

	// Verify the issued leaf chains to pebble's per-run root and covers the domain.
	inter := x509.NewCertPool()
	for _, der := range chain[1:] {
		if c, e := x509.ParseCertificate(der); e == nil {
			inter.AddCert(c)
		}
	}
	roots := fetchPebbleRoots(t, acmeHTTP)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "mail.octo-mail.test", Roots: roots, Intermediates: inter}); err != nil {
		t.Fatalf("issued cert does not verify for mail.octo-mail.test: %v", err)
	}

	t.Logf("OK: live ACME issuance via pebble (tls-alpn-01) — leaf SAN mail.octo-mail.test, notAfter=%s", leaf.NotAfter.Format(time.RFC3339))
}

// acceptHandshakes completes and closes TLS handshakes on a listener so autocert
// can answer challenges / serve issued certs.
func acceptHandshakes(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}()
	}
}

// fetchPebbleRoots retrieves pebble's per-run root CA(s) from its management API
// (https://localhost:15000/roots/0) so the issued chain can be verified.
func fetchPebbleRoots(t *testing.T, hc *http.Client) *x509.CertPool {
	pool := x509.NewCertPool()
	resp, err := hc.Get("https://localhost:15000/roots/0")
	if err != nil {
		t.Fatalf("fetch pebble root: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	if !pool.AppendCertsFromPEM(buf[:n]) {
		t.Fatalf("pebble root not parsed")
	}
	return pool
}
