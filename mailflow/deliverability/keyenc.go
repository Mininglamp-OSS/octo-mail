package deliverability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// KeyCipher encrypts DKIM private keys (and any other secret bytes) at rest with
// AES-256-GCM, so a database dump does not leak signing keys. The data key is
// derived from a master secret (e.g. from a KMS or env) via SHA-256. A nil
// KeyCipher means "store plaintext" — explicit, so tests and dev are simple and
// production must opt in.
//
// Ciphertext layout: nonce (12 bytes) || GCM sealed. A stored value that does
// not carry the magic prefix is treated as legacy plaintext on decrypt, so
// enabling encryption is a smooth migration (old keys still readable, new keys
// encrypted).
type KeyCipher struct {
	aead cipher.AEAD
}

var encMagic = []byte("MENC1")

// NewKeyCipher derives an AES-256-GCM cipher from a master secret.
func NewKeyCipher(masterSecret []byte) (*KeyCipher, error) {
	if len(masterSecret) == 0 {
		return nil, errors.New("empty master secret")
	}
	dk := sha256.Sum256(masterSecret)
	block, err := aes.NewCipher(dk[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &KeyCipher{aead: aead}, nil
}

// encrypt returns magic || nonce || sealed. Nil cipher returns plaintext.
func (c *KeyCipher) encrypt(plain []byte) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := c.aead.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(encMagic)+len(nonce)+len(sealed))
	out = append(out, encMagic...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// decrypt reverses encrypt. A value without the magic prefix is legacy plaintext
// and returned as-is (migration-friendly). A magic-prefixed value with a nil
// cipher is an error (encrypted data, no key).
func (c *KeyCipher) decrypt(stored []byte) ([]byte, error) {
	if len(stored) < len(encMagic) || !equalPrefix(stored, encMagic) {
		return stored, nil // legacy plaintext
	}
	if c == nil {
		return nil, errors.New("encrypted key present but no KeyCipher configured")
	}
	rest := stored[len(encMagic):]
	ns := c.aead.NonceSize()
	if len(rest) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, sealed := rest[:ns], rest[ns:]
	return c.aead.Open(nil, nonce, sealed, nil)
}

func equalPrefix(b, prefix []byte) bool {
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}
