package deliverability

import (
	"context"

	"github.com/mjl-/autocert"
)

// EncryptingCache wraps an autocert.Cache so certificate + ACME account private
// keys are encrypted at rest with the same KeyCipher used for DKIM keys — closing
// the gap where an operator who set OCTO_MAIL_KEY_SECRET (and saw "DKIM key
// encryption at rest enabled") would still have plaintext TLS/account keys in a DB
// dump. Every stored blob is sealed with the cache key NAME bound as GCM AAD, so a
// ciphertext can't be lifted from one cache entry to another.
//
// A nil *KeyCipher (secret unset) passes bytes through unchanged, so behavior
// matches the DKIM path: plaintext is the operator's explicit choice, encryption is
// opt-in via the master secret. Wrap only when a cipher is configured.
type EncryptingCache struct {
	Inner  autocert.Cache
	Cipher *KeyCipher
}

// Get reads and decrypts the blob for name, verifying the name-bound AAD. A decrypt
// failure (e.g. pre-existing PLAINTEXT rows from before the operator enabled
// OCTO_MAIL_KEY_SECRET, or a wrong secret) is mapped to autocert.ErrCacheMiss
// rather than surfaced as an error — so the ACME layer treats it as absent and the
// leader re-issues, overwriting the entry with a properly-encrypted blob. That makes
// enabling encryption on an existing cluster self-healing (certs re-issue once)
// rather than a hard failure. (A genuinely wrong master secret therefore also reads
// as a miss and triggers reissue — acceptable: the old blob is unreadable regardless.)
func (c EncryptingCache) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := c.Inner.Get(ctx, name)
	if err != nil {
		return nil, err // includes autocert.ErrCacheMiss, propagated unchanged
	}
	plain, derr := c.Cipher.decrypt(data, []byte(name))
	if derr != nil {
		return nil, autocert.ErrCacheMiss // undecryptable (legacy plaintext / wrong key) → reissue
	}
	return plain, nil
}

// Put encrypts the blob (name bound as AAD) and stores it.
func (c EncryptingCache) Put(ctx context.Context, name string, data []byte) error {
	sealed, err := c.Cipher.encrypt(data, []byte(name))
	if err != nil {
		return err
	}
	return c.Inner.Put(ctx, name, sealed)
}

// Delete removes name (no crypto needed).
func (c EncryptingCache) Delete(ctx context.Context, name string) error {
	return c.Inner.Delete(ctx, name)
}
