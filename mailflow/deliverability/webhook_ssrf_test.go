package deliverability

import (
	"net"
	"testing"
)

// TestIsBlockedIP covers the webhook SSRF guard's address classification: public
// IPs are allowed; loopback, private (RFC 1918 / ULA), link-local (incl. the
// 169.254.169.254 cloud metadata endpoint), unspecified, and multicast are blocked.
// IPv4-mapped IPv6 must be normalized so a mapped private address is still blocked.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",              // loopback
		"::1",                    // loopback v6
		"10.0.0.5",               // private
		"192.168.1.1",            // private
		"172.16.0.1",             // private
		"169.254.169.254",        // link-local (cloud metadata)
		"fd00::1",                // ULA
		"fe80::1",                // link-local v6
		"0.0.0.0",                // unspecified
		"224.0.0.1",              // multicast
		"::ffff:10.0.0.1",        // IPv4-mapped private
		"::ffff:169.254.169.254", // IPv4-mapped metadata
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if !isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = false, want true (must be blocked)", s)
		}
	}
	allowed := []string{
		"8.8.8.8",          // public
		"1.1.1.1",          // public
		"93.184.216.34",    // public (example.com)
		"2606:2800:220::1", // public v6
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = true, want false (public, must be allowed)", s)
		}
	}
	if !isBlockedIP(nil) {
		t.Errorf("isBlockedIP(nil) = false, want true (fail closed)")
	}
}
