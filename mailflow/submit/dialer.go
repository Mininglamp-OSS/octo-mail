package submit

import (
	"context"
	"fmt"
	"net"

	"github.com/mjl-/mox/dns"
)

// SourceIPDialer builds a Dialer that binds a chosen local (source) IP on the
// outbound TCP connection, so a multi-egress host sends from the IP selected by
// the reputation/warmup router (deliverability.IPRouter). resolveMX turns a
// recipient domain into an MX host + address to connect to; pickSource selects
// the source IP to bind (empty → OS default).
//
// This is the socket-level half of IP-pool warmup: the router decides which IP,
// this binds it as the TCP local address so the peer (and its reputation systems)
// see that exact source.
func SourceIPDialer(
	resolveMX func(ctx context.Context, domain string) (host dns.Domain, addr string, err error),
	pickSource func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error),
) Dialer {
	return func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		host, addr, err := resolveMX(ctx, domain)
		if err != nil {
			return nil, dns.Domain{}, err
		}
		d := net.Dialer{}
		if pickSource != nil {
			ip, err := pickSource(ctx, domain, host)
			if err != nil {
				return nil, dns.Domain{}, err
			}
			if ip != nil {
				d.LocalAddr = &net.TCPAddr{IP: ip}
			}
		}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, dns.Domain{}, fmt.Errorf("dial %s (%s): %w", domain, addr, err)
		}
		return conn, host, nil
	}
}
