package submit_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestDelivererSuppressionWebhookTLS proves WF-C wiring in the outbound
// deliverer: (1) a suppressed recipient is never dialed (send returns
// ErrSuppressed); (2) a successful delivery fires the OnDelivered webhook hook;
// (3) an MTA-STS enforce domain forces TLSRequiredStartTLS, so a plaintext-only
// MX fails the send.
func TestDelivererSuppressionWebhookTLS(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	ref, size, err := bs.Put(ctx, 1, strings.NewReader("From: me@sender.example\r\nTo: you@remote.example\r\nSubject: x\r\n\r\nhi\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	msg := queue.Msg{TenantID: 1, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@remote.example", BlobRef: string(ref), Size: size}

	// --- 1. Suppressed recipient: never dialed. ---
	dialed := false
	dSup := &submit.SMTPDeliverer{
		Blob: bs,
		Dial: func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			dialed = true
			return nil, dns.Domain{}, nil
		},
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSSkip,
		Suppressed: func(ctx context.Context, accID int64, rcpt string) (bool, error) {
			return rcpt == "you@remote.example", nil
		},
	}
	if err := dSup.Deliver(ctx, msg); err == nil {
		t.Fatal("suppressed recipient was sent")
	}
	if dialed {
		t.Fatal("suppressed recipient was dialed (should skip before dialing)")
	}

	// --- 2. Successful delivery fires OnDelivered. ---
	delivered := make(chan queue.Msg, 1)
	mx := &captureMX{got: make(chan string, 1)}
	dOK := &submit.SMTPDeliverer{
		Blob: bs,
		Dial: func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			c, srv := net.Pipe()
			go mx.serve(srv)
			return c, dns.Domain{ASCII: "mx.remote.example"}, nil
		},
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSSkip,
		OnDelivered:  func(ctx context.Context, m queue.Msg) { delivered <- m },
	}
	if err := dOK.Deliver(ctx, msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("OnDelivered webhook hook not fired")
	}

	// --- 3. MTA-STS enforce → TLS required → plaintext MX fails. ---
	dTLS := &submit.SMTPDeliverer{
		Blob: bs,
		Dial: func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			c, srv := net.Pipe()
			go mx.serve(srv) // plaintext MX, no STARTTLS advertised
			return c, dns.Domain{ASCII: "mx.remote.example"}, nil
		},
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSOpportunistic,
		TLSModeFor: func(ctx context.Context, domain string) (smtpclient.TLSMode, error) {
			return smtpclient.TLSRequiredStartTLS, nil // simulate MTA-STS enforce
		},
	}
	if err := dTLS.Deliver(ctx, msg); err == nil {
		t.Fatal("plaintext MX accepted under MTA-STS enforce (TLS not required)")
	}
	t.Logf("OK: suppressed→not dialed; delivered→webhook fired; MTA-STS enforce→plaintext MX rejected")
}
