package deliverability_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/mjl-/autocert"
)

// memCache is a minimal in-memory autocert.Cache for the encrypting-wrapper test.
type memCache struct{ m map[string][]byte }

func newMemCache() *memCache { return &memCache{m: map[string][]byte{}} }
func (c *memCache) Get(_ context.Context, k string) ([]byte, error) {
	if v, ok := c.m[k]; ok {
		return v, nil
	}
	return nil, autocert.ErrCacheMiss
}
func (c *memCache) Put(_ context.Context, k string, v []byte) error { c.m[k] = v; return nil }
func (c *memCache) Delete(_ context.Context, k string) error        { delete(c.m, k); return nil }

// TestEncryptingCache proves ACME cert/account keys are encrypted at rest: the
// inner blob is not plaintext, Get round-trips, a cache miss propagates as
// autocert.ErrCacheMiss, and the name is bound as AAD (a blob moved to a different
// cache key fails to decrypt — no cross-entry lifting).
func TestEncryptingCache(t *testing.T) {
	cipher, err := deliverability.NewKeyCipher([]byte("master-secret"))
	if err != nil {
		t.Fatal(err)
	}
	inner := newMemCache()
	c := deliverability.EncryptingCache{Inner: inner, Cipher: cipher}
	ctx := context.Background()

	plain := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret-key-material\n-----END EC PRIVATE KEY-----\n")
	if err := c.Put(ctx, "example.com", plain); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The stored (inner) blob must NOT be the plaintext.
	if string(inner.m["example.com"]) == string(plain) {
		t.Fatal("blob stored in plaintext — encryption not applied")
	}

	// Get round-trips to the plaintext.
	got, err := c.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("Get = %q, want %q", got, plain)
	}

	// Miss propagates as ErrCacheMiss (autocert requires the sentinel).
	if _, err := c.Get(ctx, "absent"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get(absent) = %v, want autocert.ErrCacheMiss", err)
	}

	// AAD binding: move the ciphertext to a different cache key; decrypt must fail
	// (the name is bound as GCM AAD), so a lifted blob is NOT served — it reads as a
	// cache miss (undecryptable → ErrCacheMiss, which triggers reissue), never as the
	// plaintext.
	inner.m["other.com"] = inner.m["example.com"]
	got2, err := c.Get(ctx, "other.com")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("lifted ciphertext under a different key: err=%v, want ErrCacheMiss (not served)", err)
	}
	if got2 != nil {
		t.Fatal("lifted ciphertext returned data — AAD not bound to the name")
	}

	// Self-heal: a PLAINTEXT (unencrypted) row, as would exist after enabling the
	// secret on a running cluster, is undecryptable → reads as a miss so the leader
	// reissues, rather than surfacing a hard error.
	inner.m["legacy.com"] = []byte("plaintext-pem-not-MENC2")
	if _, err := c.Get(ctx, "legacy.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("legacy plaintext row: err=%v, want ErrCacheMiss (self-heal via reissue)", err)
	}

	// Delete removes it.
	if err := c.Delete(ctx, "example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get after Delete = %v, want ErrCacheMiss", err)
	}
	t.Logf("OK: EncryptingCache seals blobs (name-bound AAD), round-trips, propagates ErrCacheMiss, resists cross-key lifting")
}
