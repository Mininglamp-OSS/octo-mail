package ha_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/ops/ha"
	"github.com/jackc/pgx/v5/pgxpool"
)

const haDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestLeaderElection proves the single-active-leader guarantee and automatic
// failover: two nodes contend for the same lock key; exactly one becomes leader;
// when the leader's connection drops (crash), a standby acquires leadership.
func TestLeaderElection(t *testing.T) {
	ctx := context.Background()

	// Node A uses its own pool so we can "crash" it by closing the pool.
	poolA, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := poolA.Ping(ctx); err != nil {
		poolA.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	poolB, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()

	const key = int64(0x6f63746f6d61696c) // "octomail"

	a := ha.New(poolA, key)
	b := ha.New(poolB, key)

	// A campaigns and wins.
	okA, err := a.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !okA {
		t.Fatalf("node A failed to acquire initial leadership")
	}
	// B campaigns and must LOSE (single active leader).
	okB, err := b.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if okB {
		t.Fatalf("node B acquired leadership while A holds it (split brain!)")
	}

	// Simulate A crashing: terminate its backend from another connection. The
	// session holding the advisory lock dies and PostgreSQL releases the lock.
	pidA := a.BackendPID()
	if pidA == 0 {
		t.Fatalf("leader A has no backend pid")
	}
	if _, err := poolB.Exec(ctx, `SELECT pg_terminate_backend($1)`, pidA); err != nil {
		t.Fatal(err)
	}

	// Split-brain guard: A's own IsLeader must now report false. PostgreSQL
	// released A's advisory lock when its backend died; IsLeader verifies lock
	// ownership server-side (pg_locks for our backend), so it detects the loss
	// even though a naive client-side Ping to a fresh pooled connection would
	// still succeed. This is the window that would otherwise let A and B both
	// believe they lead.
	if a.IsLeader(ctx) {
		t.Fatalf("crashed leader A still reports IsLeader after its backend was terminated (split-brain window)")
	}

	// B retries and now acquires leadership (automatic failover).
	acquired := false
	for i := 0; i < 100; i++ {
		ok, err := b.TryAcquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			acquired = true
			break
		}
	}
	if !acquired {
		t.Fatalf("node B did not acquire leadership after A crashed")
	}
	if !b.IsLeader(ctx) {
		t.Fatalf("node B should report itself leader after acquiring")
	}

	// B resigns → leadership is free again; a fresh node C can take it.
	if err := b.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	if b.IsLeader(ctx) {
		t.Fatalf("node B still leader after Resign")
	}
	poolC, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer poolC.Close()
	c := ha.New(poolC, key)
	okC, err := c.TryAcquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !okC {
		t.Fatalf("node C failed to acquire leadership after B resigned")
	}
	_ = c.Resign(ctx)

	t.Logf("OK: single active leader (A wins, B loses); A crash → B failover; B resign → C acquires")
}
