package auth

import "testing"

// TestAPIKeyHashVerify checks the API-key hash/verify round trip and that a
// wrong secret, empty secret, or non-apikey credential is rejected.
func TestAPIKeyHashVerify(t *testing.T) {
	const secret = "l33jqwbocaclk5atkoh6mzt7vsy4jienlkgz752nv2aztav7q"
	cred, err := HashAPIKey(secret)
	if err != nil {
		t.Fatalf("HashAPIKey: %v", err)
	}
	if cred.APIKeySHA256 == nil {
		t.Fatal("HashAPIKey produced no APIKeySHA256 field")
	}
	b, err := cred.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !VerifyAPIKey(b, secret) {
		t.Fatal("VerifyAPIKey rejected the correct secret")
	}
	if VerifyAPIKey(b, secret+"x") {
		t.Fatal("VerifyAPIKey accepted a wrong secret")
	}
	if VerifyAPIKey(b, "") {
		t.Fatal("VerifyAPIKey accepted an empty secret")
	}
	if _, err := HashAPIKey(""); err == nil {
		t.Fatal("HashAPIKey accepted an empty secret")
	}
	// A password credential must not verify as an API key (different field).
	pw, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	pb, _ := pw.Marshal()
	if VerifyAPIKey(pb, "hunter2") {
		t.Fatal("VerifyAPIKey accepted a password credential")
	}
	// Conversely, an API-key cred must not verify as a password.
	if Verify(b, secret) {
		t.Fatal("Verify (password) accepted an API-key credential")
	}
}
