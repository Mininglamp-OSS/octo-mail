package deliverability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// KeyCipher encrypts DKIM private keys (and any other secret bytes) at rest with
// AES-256-GCM, so a database dump does not leak signing keys. A nil KeyCipher
// means "store plaintext" — explicit, so tests and dev are simple and production
// must opt in (set OCTO_MAIL_KEY_SECRET).
//
// Scheme (magic "MENC2"):
//
//   - Per-record 16-byte random SALT, from which the AES-256 data key is derived
//     with HKDF-SHA256(masterSecret, salt, info="octo-mail/dkim-key-at-rest").
//     A per-record salt means two records with the same plaintext and master
//     secret still get independent keys, and the master secret is never used as a
//     raw AES key.
//   - The (tenant, domain, selector) tuple is bound as the GCM ADDITIONAL
//     AUTHENTICATED DATA, so a ciphertext cannot be lifted from one key row and
//     replayed into another (the tag won't verify under a different tuple).
//
// Ciphertext layout: "MENC2" || salt(16) || nonce(12) || GCM-sealed.
type KeyCipher struct {
	master []byte
}

var encMagic = []byte("MENC2")

const (
	keyEncSaltLen = 16
	keyEncInfo    = "octo-mail/dkim-key-at-rest"
)

// NewKeyCipher returns a KeyCipher keyed by a master secret (e.g. from a KMS or
// OCTO_MAIL_KEY_SECRET). The per-record data key is derived from it via HKDF at
// encrypt/decrypt time.
func NewKeyCipher(masterSecret []byte) (*KeyCipher, error) {
	if len(masterSecret) == 0 {
		return nil, errors.New("empty master secret")
	}
	// Copy so a caller mutating its slice can't change our key material.
	m := make([]byte, len(masterSecret))
	copy(m, masterSecret)
	return &KeyCipher{master: m}, nil
}

// aeadFor derives the per-record AES-256-GCM AEAD from the master secret and the
// record's salt via HKDF-SHA256.
func (c *KeyCipher) aeadFor(salt []byte) (cipher.AEAD, error) {
	dk, err := hkdf.Key(sha256.New, c.master, salt, keyEncInfo, 32) // AES-256
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt is the exported form of encrypt, so other packages (e.g. security/acme)
// can reuse this at-rest cipher for their own secrets. It binds aad as GCM
// additional authenticated data; a nil *KeyCipher returns plaintext (no secret).
func (c *KeyCipher) Encrypt(plain, aad []byte) ([]byte, error) { return c.encrypt(plain, aad) }

// Decrypt is the exported form of decrypt (reverses Encrypt, verifying aad).
func (c *KeyCipher) Decrypt(stored, aad []byte) ([]byte, error) { return c.decrypt(stored, aad) }

// encrypt returns "MENC2" || salt || nonce || sealed, binding aad as GCM
// additional authenticated data. A nil cipher returns plaintext (dev/no secret).
func (c *KeyCipher) encrypt(plain, aad []byte) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	salt := make([]byte, keyEncSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	aead, err := c.aeadFor(salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plain, aad)
	out := make([]byte, 0, len(encMagic)+len(salt)+len(nonce)+len(sealed))
	out = append(out, encMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// decrypt reverses encrypt, verifying aad. When a cipher is configured, a stored
// value WITHOUT the magic prefix is rejected (a hard error) rather than silently
// accepted as plaintext — there is no legacy-plaintext downgrade path. A nil
// cipher returns the stored value unchanged (plaintext mode).
func (c *KeyCipher) decrypt(stored, aad []byte) ([]byte, error) {
	if c == nil {
		// Plaintext mode: keys were stored unencrypted. A magic-prefixed value here
		// is encrypted data we have no key for — surface it rather than return garbage.
		if hasMagic(stored) {
			return nil, errors.New("encrypted key present but no KeyCipher configured")
		}
		return stored, nil
	}
	if !hasMagic(stored) {
		return nil, errors.New("stored key is not encrypted (missing MENC2 magic) but a cipher is configured")
	}
	rest := stored[len(encMagic):]
	if len(rest) < keyEncSaltLen {
		return nil, fmt.Errorf("ciphertext too short (salt)")
	}
	salt, rest := rest[:keyEncSaltLen], rest[keyEncSaltLen:]
	aead, err := c.aeadFor(salt)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(rest) < ns {
		return nil, fmt.Errorf("ciphertext too short (nonce)")
	}
	nonce, sealed := rest[:ns], rest[ns:]
	return aead.Open(nil, nonce, sealed, aad)
}

// hasMagic reports whether stored carries the MENC2 prefix.
func hasMagic(stored []byte) bool {
	return len(stored) >= len(encMagic) && string(stored[:len(encMagic)]) == string(encMagic)
}

// dkimAAD builds the additional-authenticated-data tuple that binds a DKIM key
// ciphertext to its (tenant, domain, selector) row, so it can't be lifted to a
// different row. The encrypt and decrypt call sites MUST build this identically.
// Length-prefix each field so ("a","bc") and ("ab","c") can't collide.
func dkimAAD(tenantID int64, domain, selector string) []byte {
	var b []byte
	add := func(s string) {
		b = append(b, []byte(strconv.Itoa(len(s)))...)
		b = append(b, ':')
		b = append(b, []byte(s)...)
	}
	add(strconv.FormatInt(tenantID, 10))
	add(domain)
	add(selector)
	return b
}
