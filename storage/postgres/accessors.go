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

// systemAccountName is the reserved name of the tenant + account outbound reports
// (DMARC aggregate reports) are submitted as. It is not a real mailbox login — it
// exists only to satisfy the queue's tenant_id/account_id foreign keys for
// node-originated mail that belongs to no tenant.
const systemAccountName = "__octo_system__"

// EnsureSystemAccount idempotently provisions the reserved system tenant + account
// used to send node-originated mail (outbound DMARC reports) and returns their ids.
// Safe to call on every node at startup and concurrently: the upserts are keyed on
// the unique (tenants.name) / (accounts.tenant_id, name) constraints, and the
// no-op DO UPDATE guarantees RETURNING yields the row whether it was just inserted
// or already existed.
func (s *Store) EnsureSystemAccount(ctx context.Context) (tenantID, accountID int64, err error) {
	if err = s.Pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name
		 RETURNING id`, systemAccountName).Scan(&tenantID); err != nil {
		return 0, 0, err
	}
	if err = s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id, name) VALUES ($1,$2)
		 ON CONFLICT (tenant_id, name) DO UPDATE SET name=EXCLUDED.name
		 RETURNING id`, tenantID, systemAccountName).Scan(&accountID); err != nil {
		return 0, 0, err
	}
	return tenantID, accountID, nil
}

// DomainOwned reports whether this deployment serves the given domain (a row in
// the domains table, case-insensitive). Used to gate inbound report ingestion:
// only reports about domains we actually own are stored, so an unauthenticated
// peer can neither inject fabricated report rows for an arbitrary domain nor
// pre-seed a victim's (org_name, report_id) to suppress the genuine report. On a
// query error it fails CLOSED (returns false) — a transient DB blip drops an
// unverifiable report rather than storing an unowned one.
func (s *Store) DomainOwned(ctx context.Context, domain string) bool {
	if domain == "" {
		return false
	}
	var ok bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM domains WHERE lower(domain)=lower($1))`, domain).Scan(&ok); err != nil {
		return false
	}
	return ok
}
