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

// TestReportDomainRouting proves the H18 inbound routing: mail to the configured
// report domain is accepted (it belongs to no account) and handed to the
// ReportHandler with the recipient localpart and the raw message — instead of
// being rejected as "no such recipient". A report is never bounced.
func TestReportDomainRouting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu       sync.Mutex
		gotLP    string
		gotBody  string
		gotCalls int
	)
	srv := &smtpd.Server{
		Hostname:     "mx.example.com",
		ReportDomain: "reports.example",
		ReportHandler: func(ctx context.Context, localpart string, raw []byte) {
			mu.Lock()
			defer mu.Unlock()
			gotLP = localpart
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
	if r := cmd("MAIL FROM:<reporter@remote.example>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL FROM → %q, want 250", r)
	}
	if r := cmd("RCPT TO:<dmarc-reports@reports.example>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT to report domain → %q, want 250", r)
	}
	if r := cmd("DATA"); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA → %q, want 354", r)
	}
	cli.Write([]byte("Subject: Report Domain: x\r\n\r\nreport bytes here\r\n.\r\n"))
	if r := rd(); !strings.HasPrefix(r, "250") {
		t.Fatalf("post-DATA → %q, want 250 (report accepted, never bounced)", r)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("ReportHandler called %d times, want 1", gotCalls)
	}
	if gotLP != "dmarc-reports" {
		t.Fatalf("report localpart = %q, want dmarc-reports", gotLP)
	}
	if !strings.Contains(gotBody, "report bytes here") {
		t.Fatalf("handler did not receive the message body: %.40q", gotBody)
	}
	t.Logf("OK: report-domain RCPT accepted and routed to handler (lp=%s), never bounced", gotLP)
}

// TestReportDomainNoMixedRecipients proves a report-domain recipient can't be
// combined with a normal recipient in one transaction — otherwise the report
// short-circuit in processData would silently drop the normal recipient while
// answering 250 (silent mail loss).
func TestReportDomainNoMixedRecipients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &smtpd.Server{
		Hostname:      "mx.example.com",
		ReportDomain:  "reports.example",
		ReportHandler: func(ctx context.Context, localpart string, raw []byte) {},
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
	cmd("MAIL FROM:<reporter@remote.example>")
	if r := cmd("RCPT TO:<dmarc-reports@reports.example>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("first report RCPT → %q, want 250", r)
	}
	if r := cmd("RCPT TO:<user@reports.example.notthereport>"); strings.HasPrefix(r, "250") {
		t.Fatalf("mixed normal RCPT after report → %q, want a rejection (not 250)", r)
	}
	t.Logf("OK: mixing a normal recipient with a report recipient is rejected")
}
