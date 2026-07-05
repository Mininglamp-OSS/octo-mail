package submit_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// starttlsMX is an SMTP sink that advertises STARTTLS and upgrades to TLS using
// the supplied certificate, then captures the DATA. It lets the DANE test drive a
// real TLS handshake whose peer certificate is verified against a TLSA record.
type starttlsMX struct {
	cert tls.Certificate
	got  chan string
}

func (m *starttlsMX) serve(nc net.Conn) { serveSTARTTLSMX(nc, m.cert, m.got) }

// serveSTARTTLSMX is a minimal SMTP sink advertising STARTTLS, upgrading with the
// given cert, and forwarding the received DATA to got. Shared by the DANE tests.
func serveSTARTTLSMX(nc net.Conn, cert tls.Certificate, got chan string) {
	br := bufio.NewReader(nc)
	var w net.Conn = nc
	write := func(s string) { w.Write([]byte(s + "\r\n")) }
	write("220 mx.dane.example ESMTP")
	var inData bool
	var data strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		if inData {
			if line == ".\r\n" {
				inData = false
				write("250 2.0.0 accepted")
				select {
				case got <- data.String():
				default:
				}
				continue
			}
			data.WriteString(line)
			continue
		}
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			write("250-mx.dane.example")
			write("250 STARTTLS")
		case strings.HasPrefix(up, "STARTTLS"):
			write("220 2.0.0 ready to start TLS")
			tc := tls.Server(w, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			w = tc
			br = bufio.NewReader(tc)
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			write("250 2.1.0 OK")
		case strings.HasPrefix(up, "DATA"):
			write("354 go ahead")
			inData = true
		case strings.HasPrefix(up, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 OK")
		}
	}
}

func TestOutboundDANE(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, wf6DSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}

	// Self-signed cert for the MX host.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.dane.example"},
		DNSNames:     []string{"mx.dane.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}

	// TLSA record: DANE-EE(3), SPKI(1), SHA-256(1) over the cert's SubjectPublicKeyInfo.
	spkiHash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	goodTLSA := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: spkiHash[:],
	}
	badHash := sha256.Sum256([]byte("not the real key"))
	badTLSA := goodTLSA
	badTLSA.CertAssoc = badHash[:]

	bs, _ := blob.NewFS(t.TempDir())
	raw := "From: me@sender.example\r\nTo: you@dane.example\r\nSubject: dane\r\nDate: Wed, 01 Jul 2026 10:00:00 +0000\r\nMessage-Id: <d1@sender.example>\r\n\r\nhello over DANE\r\n"
	ref, size, err := bs.Put(ctx, 1, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	msg := queue.Msg{TenantID: 1, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@dane.example", BlobRef: string(ref), Size: size}

	newDeliverer := func(tlsa adns.TLSA) (*submit.SMTPDeliverer, *starttlsMX) {
		mx := &starttlsMX{cert: cert, got: make(chan string, 1)}
		dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			c, srv := net.Pipe()
			go mx.serve(srv)
			return c, dns.Domain{ASCII: "mx.dane.example"}, nil
		}
		return &submit.SMTPDeliverer{
			Blob:         bs,
			Dial:         dialer,
			EHLOHostname: dns.Domain{ASCII: "sender.example"},
			TLSMode:      smtpclient.TLSOpportunistic,
			DANEFor: func(ctx context.Context, domain string, mxHost dns.Domain) ([]adns.TLSA, []dns.Domain, error) {
				return []adns.TLSA{tlsa}, nil, nil
			},
		}, mx
	}

	// --- 1. Correct TLSA record: DANE verifies, delivery succeeds. ---
	d, mx := newDeliverer(goodTLSA)
	if err := d.Deliver(ctx, msg); err != nil {
		t.Fatalf("delivery with correct TLSA should succeed: %v", err)
	}
	select {
	case got := <-mx.got:
		if !strings.Contains(got, "hello over DANE") {
			t.Fatalf("MX did not receive the message body:\n%s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MX did not receive the DANE-verified message")
	}

	// --- 2. Wrong TLSA record: DANE verification fails, delivery is refused. ---
	dBad, _ := newDeliverer(badTLSA)
	if err := dBad.Deliver(ctx, msg); err == nil {
		t.Fatalf("delivery with wrong TLSA record should fail (cert must not verify)")
	}

	t.Logf("OK: DANE-EE/SPKI/SHA-256 verified the MX cert (correct TLSA → deliver; wrong TLSA → refused)")
}
