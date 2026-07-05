// Package dane builds the outbound DANE (RFC 7672) TLSA lookup used by the
// submission deliverer: it resolves DNSSEC-authenticated TLSA records for a
// recipient's MX host via the smtpclient.GatherTLSA, and only returns records
// when the DNS chain is authentic (DNSSEC). Without authenticity, no records are
// returned, so delivery falls back to the configured TLS mode rather than being
// pinned to unauthenticated TLSA data (which would be a downgrade vector).
//
// The authentic gate is verified against a REAL DNSSEC validating resolver by
// TestDANEOverRealDNSSEC (gated by OCTO_MAIL_DANE_DNSSEC=1, run via
// scripts/dane-dnssec.sh): a signed zone served by nsd + validated by unbound
// yields Authentic=true and TLSA records; an unsigned zone yields Authentic=false
// and none — using octo-mail's production adns resolver, not a mock.
package deliverability

import (
	"context"

	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// Resolver is the DNSSEC-aware resolver (a DNSSEC-aware dns.Resolver; production is the
// adns StrictResolver, tests use dns.MockResolver with the authentic bit).
type Resolver interface {
	dns.Resolver
}

// Lookup is the deliverer DANEFor implementation: for the recipient domain's MX
// host, it establishes whether the host name is DNSSEC-authentic and, if so,
// gathers usable TLSA records. Returns (records, moreHostnames, err). An empty
// record set means "no DANE" (host doesn't opt in, or DNS not authentic) — the
// deliverer then keeps its default TLS mode.
func Lookup(res dns.Resolver) func(ctx context.Context, domain string, mx dns.Domain) ([]adns.TLSA, []dns.Domain, error) {
	return func(ctx context.Context, domain string, mx dns.Domain) ([]adns.TLSA, []dns.Domain, error) {
		// Establish authenticity of the MX host name via its address lookup: TLSA
		// is only trusted when the chain to the host is DNSSEC-authentic (RFC 7672).
		_, result, err := res.LookupIPAddr(ctx, mx.ASCII+".")
		if err != nil && !dns.IsNotFound(err) {
			return nil, nil, err
		}
		if !result.Authentic {
			// Host lookup not DNSSEC-authentic → do not do DANE (no downgrade).
			return nil, nil, nil
		}
		_, records, _, err := smtpclient.GatherTLSA(ctx, nil, res, mx, false, mx)
		if err != nil {
			return nil, nil, err
		}
		if len(records) == 0 {
			return nil, nil, nil
		}
		// Allowed cert names for DANE: the MX host itself (DANE-EE ignores names,
		// DANE-TA uses these). The recipient domain is also acceptable.
		names := []dns.Domain{mx}
		if d, e := dns.ParseDomain(domain); e == nil && d != mx {
			names = append(names, d)
		}
		return records, names, nil
	}
}
