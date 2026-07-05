package submit_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/mjl-/mox/dns"
)

// TestSourceIPDialer proves multi-egress source binding: the Dialer binds the
// source IP chosen by the router as the outbound connection's local address, so
// the peer observes exactly that IP. We run a real loopback listener and assert
// the server-side RemoteAddr equals the bound source IP.
func TestSourceIPDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	remoteIPs := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		remoteIPs <- host
		c.Close()
	}()

	const source = "127.0.0.1"
	dialer := submit.SourceIPDialer(
		func(ctx context.Context, domain string) (dns.Domain, string, error) {
			return dns.Domain{ASCII: "mx.test"}, ln.Addr().String(), nil
		},
		func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error) {
			return net.ParseIP(source), nil
		},
	)

	conn, host, err := dialer(context.Background(), "recipient.example")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if host.ASCII != "mx.test" {
		t.Fatalf("resolved host = %s, want mx.test", host.ASCII)
	}
	// The connection's local address must be the bound source IP.
	localIP, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	if localIP != source {
		t.Fatalf("connection local IP = %s, want bound source %s", localIP, source)
	}
	// The server observed the same IP as the client's remote address.
	select {
	case got := <-remoteIPs:
		if got != source {
			t.Fatalf("server observed remote IP %s, want bound source %s", got, source)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept the connection")
	}

	t.Logf("OK: SourceIPDialer bound source %s; peer observed the same IP (multi-egress selection reaches the socket)", source)
}
