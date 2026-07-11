package submit

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/mjl-/mox/dns"
)

// MXHost is one resolved MX candidate: the hostname (for TLS/DANE identity) and
// the "host:port" address to dial. resolveMX returns them in connection-attempt
// order (by MX preference, equal-preference hosts shuffled per RFC 5321 §5.1).
type MXHost struct {
	Host dns.Domain
	Addr string
}

// SourceIPDialer builds a Dialer that binds a chosen local (source) IP on the
// outbound TCP connection, so a multi-egress host sends from the IP selected by
// the reputation/warmup router (deliverability.IPRouter). resolveMX turns a
// recipient domain into the ordered list of MX hosts to try; pickSource selects
// the source IP to bind (empty → OS default).
//
// This is the socket-level half of IP-pool warmup: the router decides which IP,
// this binds it as the TCP local address so the peer (and its reputation systems)
// see that exact source. It also provides MX FAILOVER: the hosts are tried in
// order and the first that accepts a TCP connection wins, so a dead primary MX
// no longer fails the whole delivery attempt.
func SourceIPDialer(
	resolveMX func(ctx context.Context, domain string) ([]MXHost, error),
	pickSource func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error),
) Dialer {
	return func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		hosts, err := resolveMX(ctx, domain)
		if err != nil {
			return nil, dns.Domain{}, err
		}
		if len(hosts) == 0 {
			return nil, dns.Domain{}, fmt.Errorf("no MX hosts for %s", domain)
		}
		// Choose the source IP ONCE per delivery, before the failover loop. The
		// lease is per-tenant, not per-host, and (for the IPRouter) has a side effect
		// — it charges the IP's daily/warmup send counter. Calling it once per MX
		// tried would multiply that charge on every failover, prematurely exhausting
		// warmup caps and even falsely advancing a warmup stage on connect failures.
		// So it is bound once and reused for every candidate. The mx argument is the
		// preferred (first) MX for routing/observability; the source choice does not
		// depend on which candidate ultimately answers.
		var localAddr *net.TCPAddr
		if pickSource != nil {
			ip, err := pickSource(ctx, domain, hosts[0].Host)
			if err != nil {
				return nil, dns.Domain{}, err
			}
			if ip != nil {
				localAddr = &net.TCPAddr{IP: ip}
			}
		}
		// Try each MX in order; the first TCP connect that succeeds wins. A connect
		// failure advances to the next host (failover); the last error is returned if
		// all fail.
		var lastErr error
		for _, h := range hosts {
			d := net.Dialer{LocalAddr: localAddr}
			conn, err := d.DialContext(ctx, "tcp", h.Addr)
			if err != nil {
				lastErr = fmt.Errorf("dial %s (%s): %w", domain, h.Addr, err)
				if ctx.Err() != nil {
					return nil, dns.Domain{}, lastErr // shutting down / deadline — stop trying
				}
				continue
			}
			return conn, h.Host, nil
		}
		if lastErr == nil {
			lastErr = errors.New("no MX host reachable")
		}
		return nil, dns.Domain{}, lastErr
	}
}
