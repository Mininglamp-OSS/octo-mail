//go:build unix

package deliverability_test

import (
	"context"
	"os"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/mjl-/mox/dns"
)

// TestDANEOverRealDNSSEC proves octo-mail's DANE authentic-gate against a REAL
// DNSSEC validating resolver (not the MockResolver). deliverability.Lookup uses
// the production adns StrictResolver, which reads /etc/resolv.conf (pointed at a
// loopback validating unbound) and trusts the AD bit only because the resolver
// is loopback. For a DNSSEC-signed zone the MX host lookup is Authentic and TLSA
// records are returned; for an unsigned zone the lookup is not Authentic and no
// records are returned — no downgrade to unauthenticated TLSA data.
//
// Requires the validating-resolver rig; gated by OCTO_MAIL_DANE_DNSSEC=1 and run via
// scripts/dane-dnssec.sh (which stands up unbound + signed/unsigned zones).
func TestDANEOverRealDNSSEC(t *testing.T) {
	if os.Getenv("OCTO_MAIL_DANE_DNSSEC") != "1" {
		t.Skip("real-DNSSEC DANE test requires OCTO_MAIL_DANE_DNSSEC=1 and the unbound rig (scripts/dane-dnssec.sh)")
	}
	ctx := context.Background()

	// Production resolver path: nil adns.Resolver → adns.DefaultResolver, which
	// reads /etc/resolv.conf and applies the loopback trust-AD rule.
	res := dns.StrictResolver{Pkg: "dane-test"}
	lookup := deliverability.Lookup(res)

	// Signed zone: MX host is DNSSEC-authentic → TLSA records returned.
	records, names, err := lookup(ctx, "example.test", dns.Domain{ASCII: "mx.example.test"})
	if err != nil {
		t.Fatalf("lookup example.test: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("no TLSA records for DNSSEC-signed example.test — authentic gate rejected a genuinely-authentic chain")
	}
	if len(names) == 0 {
		t.Fatalf("no allowed cert names returned for authentic DANE")
	}
	t.Logf("signed zone: %d TLSA record(s), names=%v (Authentic chain accepted)", len(records), names)

	// Unsigned zone: MX host lookup is NOT authentic → no DANE (no downgrade).
	bogus, _, err := lookup(ctx, "bogus.test", dns.Domain{ASCII: "mx.bogus.test"})
	if err != nil {
		t.Fatalf("lookup bogus.test: %v", err)
	}
	if len(bogus) != 0 {
		t.Fatalf("TLSA records returned for UNSIGNED bogus.test (%d) — would trust unauthenticated DANE data (downgrade!)", len(bogus))
	}

	t.Logf("OK: DANE over real DNSSEC — signed zone yields authentic TLSA records; unsigned zone yields none (no downgrade). Gate enforced by a real validating resolver.")
}
