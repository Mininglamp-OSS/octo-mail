package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/autocert"
)

// pgCache is the shared, Postgres-backed ACME state store used for leader-gated
// cluster issuance: the leader writes the ACME account key and issued
// certificates here (see schema/10_acme_cache.sql), and every node reads
// certificates from it to serve TLS. It implements the autocert.Cache shape
// (Get/Put/Delete) so the storage seam stays a small, well-understood interface
// even though cluster issuance drives x/crypto/acme directly rather than autocert.
//
// It takes a *pgxpool.Pool directly, following the same convention as the other
// cross-cutting Postgres-backed components (junkfilter.NewManager, inbound.Decider).
type pgCache struct {
	pool *pgxpool.Pool
}

// newPGCache builds a Postgres-backed ACME cache over pool.
func newPGCache(pool *pgxpool.Pool) *pgCache { return &pgCache{pool: pool} }

// Get returns the data stored under name, or autocert.ErrCacheMiss if absent.
func (c *pgCache) Get(ctx context.Context, name string) ([]byte, error) {
	var data []byte
	err := c.pool.QueryRow(ctx, `SELECT data FROM acme_cache WHERE name=$1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("acme cache get %q: %w", name, err)
	}
	return data, nil
}

// Put upserts data under name and bumps updated_at (the change marker followers
// poll to detect a leader renewal).
func (c *pgCache) Put(ctx context.Context, name string, data []byte) error {
	if _, err := c.pool.Exec(ctx, acmeUpsertSQL, name, data); err != nil {
		return fmt.Errorf("acme cache put %q: %w", name, err)
	}
	return nil
}

// putTx upserts within an existing transaction — used to commit a cert write
// under the leadership epoch fence (ha.Leader.FenceExec), so a leader demoted by
// a PostgreSQL promotion cannot overwrite a newer leader's cert.
func putTx(ctx context.Context, tx pgx.Tx, name string, data []byte) error {
	if _, err := tx.Exec(ctx, acmeUpsertSQL, name, data); err != nil {
		return fmt.Errorf("acme cache put %q: %w", name, err)
	}
	return nil
}

const acmeUpsertSQL = `INSERT INTO acme_cache (name, data, updated_at) VALUES ($1, $2, now())
	 ON CONFLICT (name) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`

// Delete removes name. Absent name is not an error (autocert.Cache contract).
func (c *pgCache) Delete(ctx context.Context, name string) error {
	if _, err := c.pool.Exec(ctx, `DELETE FROM acme_cache WHERE name=$1`, name); err != nil {
		return fmt.Errorf("acme cache delete %q: %w", name, err)
	}
	return nil
}

// updatedAt returns the change marker for name, ok=false if the key is absent.
// The serving refresher uses it to reload only certificates the leader has
// renewed, without re-fetching and re-parsing the (larger) PEM bundle each tick.
func (c *pgCache) updatedAt(ctx context.Context, name string) (t time.Time, ok bool, err error) {
	e := c.pool.QueryRow(ctx, `SELECT updated_at FROM acme_cache WHERE name=$1`, name).Scan(&t)
	if errors.Is(e, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if e != nil {
		return time.Time{}, false, fmt.Errorf("acme cache updated_at %q: %w", name, e)
	}
	return t, true, nil
}
