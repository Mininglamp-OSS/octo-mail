package postgres

import (
	"context"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// Trusted account accessors: they open an account handle by a numeric id,
// bypassing the directory's authenticated resolution. They are for internal
// subsystems that already hold a trusted account id from a delivery or queue
// row (DSN generation, vacation auto-reply) — NOT for anything driven by
// unauthenticated network input, which must go through the directory.

// OpenAccountByID opens an account handle by id. name may be empty.
func (s *Store) OpenAccountByID(id, tenantID int64, name string) store.Account {
	return s.openAccount(id, tenantID, name)
}

// LookupAccountByID resolves a trusted account id to a store.Account plus its
// tenant id and name.
func (s *Store) LookupAccountByID(ctx context.Context, id int64) (store.Account, int64, string, error) {
	var tenantID int64
	var name string
	if err := s.Pool.QueryRow(ctx, `SELECT tenant_id, name FROM accounts WHERE id=$1`, id).Scan(&tenantID, &name); err != nil {
		return nil, 0, "", err
	}
	return s.openAccount(id, tenantID, name), tenantID, name, nil
}

// AccountName returns an account's name by id. Satisfies submit.AccountOpener
// (used by DSN generation to address bounce messages).
func (s *Store) AccountName(ctx context.Context, id int64) (string, error) {
	var name string
	err := s.Pool.QueryRow(ctx, `SELECT name FROM accounts WHERE id=$1`, id).Scan(&name)
	return name, err
}
