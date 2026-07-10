package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// TestEnsureSystemAccount proves the reserved send-as identity provisioner is
// idempotent: repeated calls (as would happen on every node at every startup)
// return the same tenant+account ids and create no duplicate rows. Its ids must
// reference real rows so node-originated mail (outbound DMARC reports) satisfies
// the queue's tenant_id/account_id foreign keys.
func TestEnsureSystemAccount(t *testing.T) {
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
	// Clean any prior system rows so the id-stability assertion is meaningful.
	if _, err := s.Pool.Exec(ctx,
		`DELETE FROM accounts WHERE name=$1; DELETE FROM tenants WHERE name=$1`, systemAccountName); err != nil {
		// Best-effort: FK from other rows shouldn't exist for the system name in a
		// fresh run; if cleanup fails, the idempotency assertion below still holds.
		t.Logf("cleanup note: %v", err)
	}

	tID1, aID1, err := s.EnsureSystemAccount(ctx)
	if err != nil {
		t.Fatalf("first EnsureSystemAccount: %v", err)
	}
	if tID1 == 0 || aID1 == 0 {
		t.Fatalf("got zero ids: tenant=%d account=%d", tID1, aID1)
	}
	tID2, aID2, err := s.EnsureSystemAccount(ctx)
	if err != nil {
		t.Fatalf("second EnsureSystemAccount: %v", err)
	}
	if tID1 != tID2 || aID1 != aID2 {
		t.Fatalf("ids not stable across calls: (%d,%d) then (%d,%d)", tID1, aID1, tID2, aID2)
	}
	// Exactly one row each.
	var nt, na int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE name=$1`, systemAccountName).Scan(&nt)
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM accounts WHERE name=$1`, systemAccountName).Scan(&na)
	if nt != 1 || na != 1 {
		t.Fatalf("duplicate system rows: tenants=%d accounts=%d, want 1/1", nt, na)
	}
	// The account row must actually reference the returned tenant (FK integrity).
	var gotTenant int64
	if err := s.Pool.QueryRow(ctx, `SELECT tenant_id FROM accounts WHERE id=$1`, aID2).Scan(&gotTenant); err != nil {
		t.Fatalf("system account row missing: %v", err)
	}
	if gotTenant != tID2 {
		t.Fatalf("system account tenant_id=%d, want %d", gotTenant, tID2)
	}
	t.Logf("OK: EnsureSystemAccount is idempotent (tenant %d, account %d), single row each", tID2, aID2)
}
