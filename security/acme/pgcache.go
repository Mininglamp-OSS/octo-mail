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

// Cipher is the at-rest encryption seam for the ACME secrets stored in
// acme_cache (the account private key and the per-cert private keys inside each
// bundle). It is satisfied by *deliverability.KeyCipher (AES-256-GCM), so ACME
// keys get the SAME at-rest protection as dkim_keys when OCTO_MAIL_KEY_SECRET is
// set. Kept as a local interface so security/acme need not import deliverability.
// A nil Cipher means plaintext-at-rest (an explicit, startup-logged operator
// choice — mirrors the DKIM path when no secret is configured).
type Cipher interface {
	Encrypt(plain, aad []byte) ([]byte, error)
	Decrypt(stored, aad []byte) ([]byte, error)
}

// pgCache is the shared, Postgres-backed ACME state store used for leader-gated
// cluster issuance: the leader writes the ACME account key and issued
// certificates here (see schema/10_acme_cache.sql), and every node reads
// certificates from it to serve TLS. It implements the autocert.Cache shape
// (Get/Put/Delete) so the storage seam stays a small, well-understood interface
// even though cluster issuance drives x/crypto/acme directly rather than autocert.
//
// When cipher is non-nil, stored data is AES-256-GCM encrypted at rest with the
// cache key bound as AAD (so a ciphertext can't be lifted to a different key).
//
// It takes a *pgxpool.Pool directly, following the same convention as the other
// cross-cutting Postgres-backed components (junkfilter.NewManager, inbound.Decider).
type pgCache struct {
	pool   *pgxpool.Pool
	cipher Cipher // nil = plaintext at rest
}

// newPGCache builds a Postgres-backed ACME cache over pool. cipher may be nil
// (plaintext); when set, all stored values are encrypted at rest.
func newPGCache(pool *pgxpool.Pool, cipher Cipher) *pgCache {
	return &pgCache{pool: pool, cipher: cipher}
}

// aad binds a stored value to its cache key so ciphertext can't be relocated.
func acmeAAD(name string) []byte { return []byte("octo-mail-acme:" + name) }

func (c *pgCache) seal(name string, data []byte) ([]byte, error) {
	if c.cipher == nil {
		return data, nil
	}
	return c.cipher.Encrypt(data, acmeAAD(name))
}

func (c *pgCache) open(name string, data []byte) ([]byte, error) {
	if c.cipher == nil {
		return data, nil
	}
	return c.cipher.Decrypt(data, acmeAAD(name))
}

// Get returns the (decrypted) data stored under name, or autocert.ErrCacheMiss if
// absent. A decrypt failure is returned as a real error (not a miss), so callers
// do not treat a wrong-key/corrupt value as "needs issuance".
func (c *pgCache) Get(ctx context.Context, name string) ([]byte, error) {
	var data []byte
	err := c.pool.QueryRow(ctx, `SELECT data FROM acme_cache WHERE name=$1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("acme cache get %q: %w", name, err)
	}
	plain, err := c.open(name, data)
	if err != nil {
		return nil, fmt.Errorf("acme cache decrypt %q: %w", name, err)
	}
	return plain, nil
}

// Put upserts data under name and bumps updated_at (the change marker followers
// poll to detect a leader renewal).
func (c *pgCache) Put(ctx context.Context, name string, data []byte) error {
	sealed, err := c.seal(name, data)
	if err != nil {
		return fmt.Errorf("acme cache encrypt %q: %w", name, err)
	}
	if _, err := c.pool.Exec(ctx, acmeUpsertSQL, name, sealed); err != nil {
		return fmt.Errorf("acme cache put %q: %w", name, err)
	}
	return nil
}

// putIfAbsent stores data only if name does not already exist, reporting whether
// this call created the row. Used for first-writer-wins on the ACME account key
// so two nodes racing across a failover cannot register two CA accounts.
func (c *pgCache) putIfAbsent(ctx context.Context, name string, data []byte) (created bool, err error) {
	sealed, err := c.seal(name, data)
	if err != nil {
		return false, fmt.Errorf("acme cache encrypt %q: %w", name, err)
	}
	ct, err := c.pool.Exec(ctx,
		`INSERT INTO acme_cache (name, data, updated_at) VALUES ($1, $2, now()) ON CONFLICT (name) DO NOTHING`,
		name, sealed)
	if err != nil {
		return false, fmt.Errorf("acme cache put-if-absent %q: %w", name, err)
	}
	return ct.RowsAffected() == 1, nil
}

// putTx upserts within an existing transaction — used to commit a cert write
// under the leadership epoch fence (ha.Leader.FenceExec), so a leader demoted by
// a PostgreSQL promotion cannot overwrite a newer leader's cert.
func (c *pgCache) putTx(ctx context.Context, tx pgx.Tx, name string, data []byte) error {
	sealed, err := c.seal(name, data)
	if err != nil {
		return fmt.Errorf("acme cache encrypt %q: %w", name, err)
	}
	if _, err := tx.Exec(ctx, acmeUpsertSQL, name, sealed); err != nil {
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
