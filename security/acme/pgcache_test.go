package acme

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/autocert"
)

// testDSN mirrors the other package tests (storage/postgres, junkfilter). These
// tests need real PostgreSQL and t.Skip when it is absent — a green run with no DB
// means they were skipped, not passed.
const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// openACMEPool returns a pool with the acme_cache table ensured (DDL kept in sync
// with storage/postgres/schema/10_acme_cache.sql) and truncated. It uses a raw
// pool rather than postgres.Open (which applies the full schema and needs a blob
// store) to stay self-contained — same approach as junkfilter/ha tests.
func openACMEPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS acme_cache (name text PRIMARY KEY, data bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE acme_cache`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// lazyPool returns a pool WITHOUT pinging the DB, for tests that exercise pure
// in-memory logic (host allowlist, empty-hosts rejection) and never issue a query
// — pgxpool.New connects lazily, so these run in an offline CI without Postgres.
func lazyPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Skipf("pool config invalid (%v)", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPGCacheRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := newPGCache(openACMEPool(t, ctx))

	// Miss maps to autocert.ErrCacheMiss.
	if _, err := c.Get(ctx, "cert:missing"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get miss: want ErrCacheMiss, got %v", err)
	}

	// Put then Get round-trips the exact bytes.
	want := []byte("some-pem-bytes\x00\x01")
	if err := c.Put(ctx, "cert:a", want); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "cert:a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("Get: want %q, got %q", want, got)
	}

	// updatedAt reports present after a Put.
	if _, ok, err := c.updatedAt(ctx, "cert:a"); err != nil || !ok {
		t.Fatalf("updatedAt: ok=%v err=%v, want ok=true", ok, err)
	}

	// Put overwrites and bumps updated_at.
	t0, _, _ := c.updatedAt(ctx, "cert:a")
	if err := c.Put(ctx, "cert:a", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	t1, _, _ := c.updatedAt(ctx, "cert:a")
	if !t1.After(t0) && !t1.Equal(t0) { // now() resolution: at least not before
		t.Fatalf("updated_at not advanced: %v -> %v", t0, t1)
	}
	if got, _ := c.Get(ctx, "cert:a"); string(got) != "v2" {
		t.Fatalf("overwrite: got %q", got)
	}

	// Delete removes; deleting a missing key is not an error.
	if err := c.Delete(ctx, "cert:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "cert:a"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get after delete: want ErrCacheMiss, got %v", err)
	}
	if err := c.Delete(ctx, "cert:a"); err != nil {
		t.Fatalf("Delete missing: want nil, got %v", err)
	}
}
