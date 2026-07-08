package smtpd_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
)

// TestBounceDomainRouting proves the H9 inbound routing: mail to the configured
// VERP bounce domain is accepted (it belongs to no account) and handed to the
// BounceHandler with the VERP recipient localpart and the raw message — instead
// of being rejected as "no such recipient". A bounce is never bounced.
func TestBounceDomainRouting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu       sync.Mutex
		gotVERP  string
		gotBody  string
		gotCalls int
	)
	srv := &smtpd.Server{
		Hostname:     "mx.example.com",
		BounceDomain: "bounces.example",
		BounceHandler: func(ctx context.Context, verpLocalpart string, raw []byte) {
			mu.Lock()
			defer mu.Unlock()
			gotVERP = verpLocalpart
			gotBody = string(raw)
			gotCalls++
		},
	}
	cli, s := net.Pipe()
	go func() { _ = srv.Serve(ctx, s) }()
	_ = cli.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(cli)
	rd := func() string { line, _ := br.ReadString('\n'); return strings.TrimSpace(line) }
	cmd := func(line string) string { cli.Write([]byte(line + "\r\n")); return rd() }

	rd() // greeting
	cli.Write([]byte("EHLO client\r\n"))
	for {
		line, _ := br.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	// A remote MX bounces to our VERP address (null sender, as bounces use).
	if r := cmd("MAIL FROM:<>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL FROM:<> → %q, want 250", r)
	}
	// RCPT to the bounce domain must be accepted (not "no such recipient").
	if r := cmd("RCPT TO:<bounces+7.42@bounces.example>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT to bounce domain → %q, want 250", r)
	}
	if r := cmd("DATA"); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA → %q, want 354", r)
	}
	cli.Write([]byte("Subject: failure notice\r\n\r\n550 user unknown\r\n.\r\n"))
	if r := rd(); !strings.HasPrefix(r, "250") {
		t.Fatalf("post-DATA → %q, want 250 (bounce accepted, never re-bounced)", r)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("BounceHandler called %d times, want 1", gotCalls)
	}
	if gotVERP != "bounces+7.42" {
		t.Fatalf("VERP localpart = %q, want bounces+7.42", gotVERP)
	}
	if !strings.Contains(gotBody, "user unknown") {
		t.Fatalf("handler did not receive the message body: %.40q", gotBody)
	}
	t.Logf("OK: bounce-domain RCPT accepted and routed to handler (verp=%s), never re-bounced", gotVERP)
}
