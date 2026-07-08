package deliverability_test

import (
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
)

// TestSignedVERP proves the HMAC-signed VERP token round-trips and that a forged
// or tampered token fails authentication (closing the cross-tenant attribution
// DoS), while the keyless fallback still round-trips via the unsigned form.
func TestSignedVERP(t *testing.T) {
	key := []byte("a-secret-verp-key")

	// Round-trip: sign then parse yields the same (tenant, msg).
	tok := deliverability.SignedVERPToken(7, 42, key)
	ti, mi, ok := deliverability.ParseSignedVERP(tok, key)
	if !ok || ti != 7 || mi != 42 {
		t.Fatalf("roundtrip: ok=%v ti=%d mi=%d (tok=%q)", ok, ti, mi, tok)
	}

	// A different key must not verify.
	if _, _, ok := deliverability.ParseSignedVERP(tok, []byte("other-key")); ok {
		t.Fatal("token verified under the wrong key")
	}

	// A forged token (guessed tenant/msg, no valid MAC) must not verify.
	if _, _, ok := deliverability.ParseSignedVERP("bounces+7.42.aaaaaaaaaaaaaaaa", key); ok {
		t.Fatal("forged token with bogus MAC verified")
	}
	// An unsigned token must not verify when a key is required.
	if _, _, ok := deliverability.ParseSignedVERP("bounces+7.42", key); ok {
		t.Fatal("unsigned token verified when key was set")
	}

	// Tamper: changing the tenant id invalidates the MAC.
	tampered := "bounces+8." + tok[len("bounces+7."):] // swap tenant 7→8, keep old MAC
	if _, _, ok := deliverability.ParseSignedVERP(tampered, key); ok {
		t.Fatal("tampered tenant id still verified")
	}

	// Keyless fallback: SignedVERPToken == unsigned, and ParseSignedVERP accepts it.
	if got := deliverability.SignedVERPToken(3, 9, nil); got != deliverability.VERPToken(3, 9) {
		t.Fatalf("keyless token = %q, want unsigned form", got)
	}
	if ti, mi, ok := deliverability.ParseSignedVERP("bounces+3.9", nil); !ok || ti != 3 || mi != 9 {
		t.Fatalf("keyless parse: ok=%v ti=%d mi=%d", ok, ti, mi)
	}
	t.Logf("OK: signed VERP round-trips; wrong-key/forged/tampered/unsigned rejected; keyless fallback works")
}
