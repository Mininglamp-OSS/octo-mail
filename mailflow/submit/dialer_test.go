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
		func(ctx context.Context, domain string) ([]submit.MXHost, error) {
			return []submit.MXHost{{Host: dns.Domain{ASCII: "mx.test"}, Addr: ln.Addr().String()}}, nil
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

// TestSourceIPDialerFailover proves #25-4: when the first MX candidate refuses
// the TCP connection, the dialer advances to the next candidate rather than
// failing the whole delivery attempt. The first host points at a closed port; the
// second at a live listener. The dialer must return the live host.
func TestSourceIPDialerFailover(t *testing.T) {
	// A live listener for the SECOND candidate.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		c.Close()
	}()

	// A dead address for the FIRST candidate: bind then immediately close so the
	// port is (almost certainly) refused.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	dialer := submit.SourceIPDialer(
		func(ctx context.Context, domain string) ([]submit.MXHost, error) {
			return []submit.MXHost{
				{Host: dns.Domain{ASCII: "mx1.dead"}, Addr: deadAddr},
				{Host: dns.Domain{ASCII: "mx2.live"}, Addr: ln.Addr().String()},
			}, nil
		},
		nil, // no source-IP selection
	)

	conn, host, err := dialer(context.Background(), "recipient.example")
	if err != nil {
		t.Fatalf("dial with failover: %v", err)
	}
	defer conn.Close()
	if host.ASCII != "mx2.live" {
		t.Fatalf("failover host = %s, want mx2.live (should have skipped the dead primary)", host.ASCII)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("live MX did not accept the failover connection")
	}
	t.Logf("OK: dialer failed over from a refused primary MX to the live secondary")
}

// TestSourceIPDialerAllDown proves the dialer returns an error (not a nil conn)
// when every MX candidate is unreachable.
func TestSourceIPDialerAllDown(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	dialer := submit.SourceIPDialer(
		func(ctx context.Context, domain string) ([]submit.MXHost, error) {
			return []submit.MXHost{{Host: dns.Domain{ASCII: "mx.dead"}, Addr: deadAddr}}, nil
		},
		nil,
	)
	if _, _, err := dialer(context.Background(), "recipient.example"); err == nil {
		t.Fatal("expected an error when all MX candidates are down, got nil")
	}
}
