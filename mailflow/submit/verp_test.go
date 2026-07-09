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

// verpMX captures the MAIL FROM line the deliverer transmits.
type verpMX struct{ mailFrom chan string }

func (m *verpMX) serve(nc net.Conn) {
	br := bufio.NewReader(nc)
	w := func(s string) { nc.Write([]byte(s + "\r\n")) }
	w("220 mx.remote.example ESMTP")
	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if line == ".\r\n" {
				inData = false
				w("250 2.0.0 accepted")
			}
			continue
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			w("250 mx.remote.example")
		case strings.HasPrefix(up, "MAIL"):
			select {
			case m.mailFrom <- strings.TrimSpace(line):
			default:
			}
			w("250 2.1.0 OK")
		case strings.HasPrefix(up, "RCPT"):
			w("250 2.1.5 OK")
		case strings.HasPrefix(up, "DATA"):
			w("354 go ahead")
			inData = true
		case strings.HasPrefix(up, "QUIT"):
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

// TestVERPEnvelopeRewrite proves the H9 outbound half: when EnvelopeFrom is set,
// the transmitted SMTP MAIL FROM is the VERP bounce address (attributing bounces
// to the tenant), while with EnvelopeFrom nil the original sender is transmitted.
func TestVERPEnvelopeRewrite(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: hi\r\n\r\nbody\r\n"
	ref, size, err := bs.Put(ctx, 7, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	m := queue.Msg{ID: 42, TenantID: 7, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@remote.example", BlobRef: string(ref), Size: size}

	deliver := func(envFrom func(queue.Msg) string) string {
		mx := &verpMX{mailFrom: make(chan string, 1)}
		d := &submit.SMTPDeliverer{
			Blob:         bs,
			EHLOHostname: dns.Domain{ASCII: "sender.example"},
			TLSMode:      smtpclient.TLSSkip,
			EnvelopeFrom: envFrom,
			Dial: func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
				c, srv := net.Pipe()
				go mx.serve(srv)
				return c, dns.Domain{ASCII: "mx.remote.example"}, nil
			},
		}
		if err := d.Deliver(ctx, m); err != nil {
			t.Fatalf("deliver: %v", err)
		}
		select {
		case mf := <-mx.mailFrom:
			return mf
		case <-time.After(5 * time.Second):
			t.Fatal("no MAIL FROM captured")
			return ""
		}
	}

	// VERP enabled: envelope is the bounce address, not the original sender.
	got := deliver(func(x queue.Msg) string { return "bounces+7.42@bounces.example" })
	if !strings.Contains(strings.ToLower(got), "<bounces+7.42@bounces.example>") {
		t.Fatalf("VERP MAIL FROM = %q, want bounces+7.42@bounces.example", got)
	}

	// VERP disabled: the original sender is transmitted.
	got = deliver(nil)
	if !strings.Contains(strings.ToLower(got), "<me@sender.example>") {
		t.Fatalf("non-VERP MAIL FROM = %q, want me@sender.example", got)
	}
	t.Logf("OK: EnvelopeFrom set → VERP envelope; nil → original sender")
}
