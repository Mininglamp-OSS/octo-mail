// Package auth handles credential hashing and verification for principals.
// Passwords are stored as argon2id hashes (never plaintext) in principals.cred.
// This closes the "credential verification is stubbed" boundary: after this,
// wrong passwords are rejected.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/mjl-/mox/scram"
	"golang.org/x/crypto/argon2"
)

// argon2id parameters. Conservative defaults; tunable per deployment.
const (
	a2Time    = 1
	a2Memory  = 64 * 1024 // 64 MiB
	a2Threads = 4
	a2KeyLen  = 32
	a2SaltLen = 16
)

// scramIterations is the PBKDF2 iteration count for SCRAM-SHA-256 verifiers.
const scramIterations = 4096

// Cred is the JSON structure stored in principals.cred (and api_keys.cred).
type Cred struct {
	Argon2id *Argon2idCred `json:"argon2id,omitempty"`
	// ScramSHA256 is a salted verifier enabling the SASL SCRAM-SHA-256 exchange
	// without the server ever holding the plaintext password.
	ScramSHA256 *ScramCred `json:"scram_sha256,omitempty"`
	// APIKeySHA256 is a hash of an API key's secret half. API keys are
	// high-entropy random tokens, so a fast SHA-256 (constant-time compared) is
	// sufficient and avoids the per-request cost of argon2.
	APIKeySHA256 *APIKeyCred `json:"apikey_sha256,omitempty"`
	// Future: TLS pubkey fingerprints, app passwords.
}

// Argon2idCred holds an argon2id password verifier.
type Argon2idCred struct {
	Salt    string `json:"salt"` // base64
	Hash    string `json:"hash"` // base64
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	KeyLen  uint32 `json:"k"`
}

// ScramCred holds a SCRAM-SHA-256 salted-password verifier.
type ScramCred struct {
	Salt           string `json:"salt"`  // base64
	SaltedPassword string `json:"spwd"`  // base64
	Iterations     int    `json:"iters"` // PBKDF2 iterations
}

// APIKeyCred holds a SHA-256 hash of an API key's secret half.
type APIKeyCred struct {
	Hash string `json:"hash"` // base64 of sha256(secret)
}

// HashPassword produces a Cred for storage from a plaintext password. It stores
// both an argon2id verifier (for LOGIN/PLAIN) and a SCRAM-SHA-256 salted
// verifier (for AUTHENTICATE SCRAM-SHA-256).
func HashPassword(password string) (Cred, error) {
	if password == "" {
		return Cred{}, fmt.Errorf("empty password")
	}
	salt := make([]byte, a2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Cred{}, err
	}
	key := argon2.IDKey([]byte(password), salt, a2Time, a2Memory, a2Threads, a2KeyLen)

	scramSalt := scram.MakeRandom()
	saltedPwd, err := scram.SaltPassword(sha256.New, password, scramSalt, scramIterations)
	if err != nil {
		return Cred{}, err
	}

	return Cred{
		Argon2id: &Argon2idCred{
			Salt:    base64.StdEncoding.EncodeToString(salt),
			Hash:    base64.StdEncoding.EncodeToString(key),
			Time:    a2Time,
			Memory:  a2Memory,
			Threads: a2Threads,
			KeyLen:  a2KeyLen,
		},
		ScramSHA256: &ScramCred{
			Salt:           base64.StdEncoding.EncodeToString(scramSalt),
			SaltedPassword: base64.StdEncoding.EncodeToString(saltedPwd),
			Iterations:     scramIterations,
		},
	}, nil
}

// Marshal serializes a Cred to jsonb bytes.
func (c Cred) Marshal() ([]byte, error) { return json.Marshal(c) }

// Verify reports whether password matches the stored credential. Constant-time.
// Returns false (not an error) on any mismatch or missing verifier.
func Verify(credJSON []byte, password string) bool {
	var c Cred
	if err := json.Unmarshal(credJSON, &c); err != nil || c.Argon2id == nil {
		return false
	}
	a := c.Argon2id
	salt, err := base64.StdEncoding.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(a.Hash)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, a.KeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// SCRAMVerifier decodes the stored SCRAM-SHA-256 verifier (salt, salted
// password, iterations) for driving the SASL exchange. Returns ok=false when no
// SCRAM verifier is stored for this credential.
func SCRAMVerifier(credJSON []byte) (salt, saltedPassword []byte, iterations int, ok bool) {
	var c Cred
	if err := json.Unmarshal(credJSON, &c); err != nil || c.ScramSHA256 == nil {
		return nil, nil, 0, false
	}
	sc := c.ScramSHA256
	salt, err := base64.StdEncoding.DecodeString(sc.Salt)
	if err != nil {
		return nil, nil, 0, false
	}
	saltedPassword, err = base64.StdEncoding.DecodeString(sc.SaltedPassword)
	if err != nil {
		return nil, nil, 0, false
	}
	return salt, saltedPassword, sc.Iterations, true
}

// HashAPIKey produces a Cred storing a SHA-256 hash of an API key's secret half.
// API keys are high-entropy random tokens, so a plain (fast) hash with a
// constant-time compare is standard and appropriate — unlike passwords, they do
// not need a slow KDF.
func HashAPIKey(secret string) (Cred, error) {
	if secret == "" {
		return Cred{}, fmt.Errorf("empty api key secret")
	}
	sum := sha256.Sum256([]byte(secret))
	return Cred{
		APIKeySHA256: &APIKeyCred{
			Hash: base64.StdEncoding.EncodeToString(sum[:]),
		},
	}, nil
}

// VerifyAPIKey reports whether secret matches the stored API-key credential.
// Constant-time; returns false (not an error) on any mismatch or missing hash.
func VerifyAPIKey(credJSON []byte, secret string) bool {
	var c Cred
	if err := json.Unmarshal(credJSON, &c); err != nil || c.APIKeySHA256 == nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(c.APIKeySHA256.Hash)
	if err != nil {
		return false
	}
	got := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
