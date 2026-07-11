package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/autocert"
)

// AcmeCache implements autocert.Cache over Postgres (the acme_cache table), so a
// stateless cluster shares one ACME account key + certificate set instead of each
// node keeping node-local state. It is the storage half of the leader-gated
// cluster-ACME model (issue #32): the leader orders certs and Puts them here;
// followers Get certs — and tls-alpn-01 challenge token certs — from here, so any
// node's :443 can answer a validation the leader started.
//
// Keys are autocert cache keys (opaque to us): "<domain>", "<domain>+rsa",
// "<domain>+token", "acme_account+key". Safe for concurrent use (the pool is).
type AcmeCache struct{ Pool *pgxpool.Pool }

// Get returns the cached blob for name, or autocert.ErrCacheMiss if absent (the
// sentinel autocert's issuance logic keys off — a plain nil/empty would break it).
func (c AcmeCache) Get(ctx context.Context, name string) ([]byte, error) {
	var data []byte
	err := c.Pool.QueryRow(ctx, `SELECT data FROM acme_cache WHERE name=$1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Put stores (or replaces) the blob for name.
func (c AcmeCache) Put(ctx context.Context, name string, data []byte) error {
	_, err := c.Pool.Exec(ctx,
		`INSERT INTO acme_cache (name, data, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		name, data)
	return err
}

// Delete removes name. Per the autocert.Cache contract, deleting an absent key is
// not an error (a bare DELETE affecting zero rows returns nil).
func (c AcmeCache) Delete(ctx context.Context, name string) error {
	_, err := c.Pool.Exec(ctx, `DELETE FROM acme_cache WHERE name=$1`, name)
	return err
}
