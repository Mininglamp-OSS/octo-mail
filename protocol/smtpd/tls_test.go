package smtpd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.sender.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"mail.sender.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// TestSubmissionRequiresSTARTTLS proves the submission-AUTH-over-TLS boundary:
// on a TLS-configured submission listener, AUTH is refused before STARTTLS, and
// a real client that performs STARTTLS then AUTH PLAIN succeeds and enqueues.
// Driven by an unmodified smtpclient with TLSRequiredStartTLS.
func TestSubmissionRequiresSTARTTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, senderID, sdom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, tenantID).Scan(&sdom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "s3cret"); err != nil {
		t.Fatal(err)
	}

	subSrv := &smtpd.Server{
		Dir:        dir,
		Hostname:   "mail.sender.example",
		Submission: &submit.Submitter{Pool: s.Pool, Blob: bs},
		TLSConfig:  selfSignedTLS(t),
	}
	subCli, subConn := net.Pipe()
	go func() { _ = subSrv.Serve(ctx, subConn) }()
	_ = subCli.SetDeadline(time.Now().Add(20 * time.Second))

	// TLSRequiredStartTLS: client performs STARTTLS, then AUTH over the encrypted
	// channel. If the server had offered AUTH in clear, this same client would
	// have sent credentials unencrypted — it does not, because AUTH is withheld
	// until TLS.
	cl, err := smtpclient.New(ctx, nil, subCli,
		smtpclient.TLSRequiredStartTLS, false,
		dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mail.sender.example"},
		smtpclient.Opts{
			TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "mail.sender.example"},
			Auth: func(mechs []string, cs *tls.ConnectionState) (sasl.Client, error) {
				return sasl.NewClientPlain("me@sender.example", "s3cret"), nil
			},
		})
	if err != nil {
		t.Fatalf("smtpclient new (starttls+auth): %v", err)
	}
	defer cl.Close()

	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: tls\r\n\r\nover starttls\r\n"
	if err := cl.Deliver(ctx, "me@sender.example", "you@remote.example", int64(len(raw)), strings.NewReader(raw), false, false, false); err != nil {
		t.Fatalf("submission over STARTTLS deliver: %v", err)
	}
	var q int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("expected 1 queued outbound after STARTTLS+AUTH submission, got %d", q)
	}
	t.Logf("OK: submission AUTH withheld until STARTTLS; real client did STARTTLS→AUTH→enqueue")
}
