package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// TestTenantQuotaEnforced proves the H5 fix (#7): the per-tenant byte quota is
// enforced, not just the per-account one. With the tenant counter near a tenant
// cap and account quotas unlimited, CanAddMessageSize rejects a message that
// would push the tenant over — so a tenant cap can't be exceeded by spreading
// messages across accounts.
func TestTenantQuotaEnforced(t *testing.T) {
	ctx := context.Background()
	s, _, accID := setupTest(t)

	var tenantID int64
	must(t, s.Pool.QueryRow(ctx, `SELECT tenant_id FROM accounts WHERE id=$1`, accID).Scan(&tenantID))
	// Tenant cap = 1000 bytes; account quota left unlimited (NULL).
	if _, err := s.Pool.Exec(ctx, `UPDATE tenants SET quota_bytes=1000 WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	var acc2 int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u2') RETURNING id`, tenantID).Scan(&acc2))
	// Seed the tenant usage counter (scope_type=0) near the cap.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO quota_counters (scope_type, scope_id, bytes_used, msg_count) VALUES (0,$1,900,1)`, tenantID); err != nil {
		t.Fatal(err)
	}

	openAcc := func(id int64) store.Account {
		a, _, _, err := s.LookupAccountByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	canAdd := func(a store.Account, size int64) bool {
		var ok bool
		if err := a.Tx(ctx, func(tx store.Tx) error {
			v, _, e := a.CanAddMessageSize(tx, size)
			ok = v
			return e
		}); err != nil {
			t.Fatalf("CanAddMessageSize(%d): %v", size, err)
		}
		return ok
	}

	// 50 bytes fits (900+50 <= 1000).
	if !canAdd(openAcc(accID), 50) {
		t.Fatal("50-byte message rejected, want accepted (under tenant cap)")
	}
	// 200 bytes does NOT (900+200 > 1000), from a DIFFERENT account whose own
	// quota is unlimited — the tenant cap binds across accounts.
	if canAdd(openAcc(acc2), 200) {
		t.Fatal("200-byte message accepted, want rejected (tenant cap exceeded across accounts)")
	}
	t.Logf("OK: per-tenant quota enforced across accounts (account unlimited, tenant cap binds)")
}
