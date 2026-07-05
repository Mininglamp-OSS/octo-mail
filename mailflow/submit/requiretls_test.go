package submit_test

import (
	"bufio"
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

// plaintextMX is a minimal SMTP sink that does NOT advertise STARTTLS: it can
// only receive in the clear. It lets the RequireTLS test prove that a
// TLS-required message refuses to deliver here, while a policy/plaintext-allowed
// message goes through.
func servePlaintextMX(nc net.Conn, got chan string) {
	br := bufio.NewReader(nc)
	write := func(s string) { nc.Write([]byte(s + "\r\n")) }
	write("220 mx.plain.example ESMTP")
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
			write("250 mx.plain.example") // no STARTTLS advertised
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

// TestRequireTLSOverride proves the per-message RequireTLS flag is honored at
// delivery: against a plaintext-only MX, RequireTLS=true refuses to deliver (no
// downgrade), while RequireTLS=false (and nil opportunistic) delivers.
func TestRequireTLSOverride(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	raw := "From: me@sender.example\r\nTo: you@plain.example\r\nSubject: rt\r\n\r\nhello\r\n"
	ref, size, err := bs.Put(ctx, 1, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	newDeliverer := func() (*submit.SMTPDeliverer, chan string) {
		got := make(chan string, 1)
		dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
			c, srv := net.Pipe()
			go servePlaintextMX(srv, got)
			return c, dns.Domain{ASCII: "mx.plain.example"}, nil
		}
		return &submit.SMTPDeliverer{
			Blob:         bs,
			Dial:         dialer,
			EHLOHostname: dns.Domain{ASCII: "sender.example"},
			TLSMode:      smtpclient.TLSOpportunistic,
		}, got
	}

	yes, no := true, false
	base := queue.Msg{TenantID: 1, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@plain.example", BlobRef: string(ref), Size: size}

	// RequireTLS=true → must refuse (plaintext MX offers no STARTTLS).
	d1, _ := newDeliverer()
	m1 := base
	m1.RequireTLS = &yes
	if err := d1.Deliver(ctx, m1); err == nil {
		t.Fatalf("RequireTLS=true should refuse delivery to a plaintext-only MX")
	}

	// RequireTLS=false → allowed to deliver in the clear.
	d2, got2 := newDeliverer()
	m2 := base
	m2.RequireTLS = &no
	if err := d2.Deliver(ctx, m2); err != nil {
		t.Fatalf("RequireTLS=false should deliver over plaintext: %v", err)
	}
	select {
	case body := <-got2:
		if !strings.Contains(body, "hello") {
			t.Fatalf("MX did not receive body:\n%s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequireTLS=false delivery did not reach MX")
	}

	// nil (opportunistic policy) → also delivers in the clear here.
	d3, got3 := newDeliverer()
	if err := d3.Deliver(ctx, base); err != nil {
		t.Fatalf("nil RequireTLS opportunistic should deliver: %v", err)
	}
	select {
	case <-got3:
	case <-time.After(5 * time.Second):
		t.Fatal("opportunistic delivery did not reach MX")
	}

	t.Logf("OK: RequireTLS=true refused plaintext MX; false/nil delivered")
}
