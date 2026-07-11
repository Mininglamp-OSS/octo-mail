package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/autocert"
)

// TestAcmeCache proves the Postgres-backed autocert.Cache contract (issue #32):
// Put/Get round-trips, a missing key returns autocert.ErrCacheMiss (the sentinel
// autocert's issuance logic requires), Put overwrites, and Delete removes a key
// and is a no-op (nil error) for an absent one.
func TestAcmeCache(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE acme_cache`); err != nil {
		t.Fatal(err)
	}
	c := AcmeCache{Pool: s.Pool}

	// Miss on an absent key → ErrCacheMiss (not a generic error / nil).
	if _, err := c.Get(ctx, "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get(absent) = %v, want autocert.ErrCacheMiss", err)
	}

	// Put then Get round-trips the exact bytes.
	want := []byte("\x00\x01PEM-ish blob\xff")
	if err := c.Put(ctx, "example.com", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("Get = %q, want %q", got, want)
	}

	// Put again overwrites (upsert), doesn't error or duplicate.
	want2 := []byte("replacement")
	if err := c.Put(ctx, "example.com", want2); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	got, _ = c.Get(ctx, "example.com")
	if string(got) != string(want2) {
		t.Fatalf("after overwrite Get = %q, want %q", got, want2)
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM acme_cache WHERE name='example.com'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("overwrite produced %d rows, want 1", n)
	}

	// Distinct keys are independent (e.g. the token / account-key namespaces).
	if err := c.Put(ctx, "example.com+token", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "acme_account+key", []byte("acct")); err != nil {
		t.Fatal(err)
	}

	// Delete removes the key; a subsequent Get misses.
	if err := c.Delete(ctx, "example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get after Delete = %v, want ErrCacheMiss", err)
	}
	// The other keys survived.
	if _, err := c.Get(ctx, "acme_account+key"); err != nil {
		t.Fatalf("unrelated key removed by Delete: %v", err)
	}

	// Deleting an absent key is not an error (autocert.Cache contract).
	if err := c.Delete(ctx, "does-not-exist"); err != nil {
		t.Fatalf("Delete(absent) = %v, want nil", err)
	}
	t.Logf("OK: AcmeCache Get/Put/Delete satisfy the autocert.Cache contract (ErrCacheMiss, upsert, nil-on-absent-delete)")
}
