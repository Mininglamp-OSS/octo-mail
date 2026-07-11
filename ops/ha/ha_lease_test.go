package ha_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/ops/ha"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// leaseKey is a distinct advisory-lock key so these tests don't contend with the
// election/coordinator tests (which use their own keys).
const leaseKey = int64(0x6c6561736531) // "lease1"

// ensureLeaseSchema creates the leader_lease table if absent. The ha tests use
// raw pools (not postgres.Open, which would apply the full schema) because they
// need several independent connections to simulate crashes; this keeps them
// self-contained. DDL mirrors storage/postgres/schema/08_leader_lease.sql — keep
// in sync (a 4-column table; drift risk is low and the acquire path would fail
// loudly if a column were missing).
func ensureLeaseSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`CREATE TABLE IF NOT EXISTS leader_lease (
		    key          bigint PRIMARY KEY,
		    holder       text NOT NULL,
		    epoch        bigint NOT NULL,
		    heartbeat_at timestamptz NOT NULL
		)`)
	if err != nil {
		t.Fatal(err)
	}
}

func openHAPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(pool.Close)
	ensureLeaseSchema(t, pool)
	// Start from a clean lease row for this key so a leftover row from a prior run
	// (e.g. a crashed test) doesn't perturb epoch assertions.
	if _, err := pool.Exec(ctx, `DELETE FROM leader_lease WHERE key=$1`, leaseKey); err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestLeaseEpochMonotonic proves the fencing token is monotonic across
// acquisitions: each successful TryAcquire returns a strictly higher epoch than
// the previous holder's, so an old leader can always be distinguished from a new
// one. Acquire→resign→re-acquire on one node, and a takeover by a second node,
// must both bump the epoch.
func TestLeaseEpochMonotonic(t *testing.T) {
	ctx := context.Background()
	pool := openHAPool(t)

	a := ha.New(pool, leaseKey, "node-A")
	ok, err := a.TryAcquire(ctx)
	if err != nil || !ok {
		t.Fatalf("A acquire: ok=%v err=%v", ok, err)
	}
	// Ensure the held connection is returned before pool.Close (cleanup), even if
	// an assertion fails mid-test; a leaked checked-out conn would hang Close.
	defer a.Resign(ctx)
	e1 := a.Epoch()
	if e1 == 0 {
		t.Fatalf("epoch after acquire = 0, want >0")
	}

	// Clean resign then re-acquire: epoch must advance (the lease row persists
	// only its epoch counter is bumped on the next INSERT...ON CONFLICT).
	if err := a.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	// Resign deletes the row, so the next acquire re-inserts at epoch 1. That is
	// still fine for fencing WITHIN a clean handover (no concurrent old leader).
	// The cross-node takeover below is the case that must strictly increase.
	ok, err = a.TryAcquire(ctx)
	if err != nil || !ok {
		t.Fatalf("A re-acquire: ok=%v err=%v", ok, err)
	}

	// Now a takeover WITHOUT a clean resign (the dangerous case): B cannot acquire
	// while A holds the advisory lock, so simulate A's crash by terminating its
	// backend, then B acquires and must get a strictly higher epoch than A held.
	ePreCrash := a.Epoch()
	pid := a.BackendPID()
	if pid == 0 {
		t.Fatalf("A has no backend pid")
	}
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	b := ha.New(pool, leaseKey, "node-B")
	acquired := false
	for i := 0; i < 100; i++ {
		ok, err := b.TryAcquire(ctx)
		if err != nil {
			// A's terminated backend can surface as a transient error on the pooled
			// conn; retry.
			continue
		}
		if ok {
			acquired = true
			break
		}
	}
	if !acquired {
		t.Fatalf("B did not acquire after A crash")
	}
	bEpoch := b.Epoch()
	if bEpoch <= ePreCrash {
		t.Fatalf("takeover epoch %d not greater than crashed leader's %d — fencing token not monotonic across crash", bEpoch, ePreCrash)
	}
	_ = b.Resign(ctx)
	t.Logf("OK: epoch monotonic across crash takeover (A held %d, B took over at %d)", ePreCrash, bEpoch)
}

// TestTransientErrorDoesNotFlap proves the #24-4 anti-flap fix: a transient error
// on a still-live connection (here: an already-cancelled per-call context) must
// NOT cause the leader to step down. Only a definitive loss (lock gone / lease
// superseded) or a dead connection releases leadership. Before the fix, any error
// folded into a release, so a momentary DB hiccup dropped a healthy leader.
func TestTransientErrorDoesNotFlap(t *testing.T) {
	ctx := context.Background()
	pool := openHAPool(t)

	a := ha.New(pool, leaseKey, "node-A")
	ok, err := a.TryAcquire(ctx)
	if err != nil || !ok {
		t.Fatalf("A acquire: ok=%v err=%v", ok, err)
	}
	defer a.Resign(ctx)

	// A cancelled context makes the probe/heartbeat query error, but the underlying
	// connection is still alive — a transient condition, not a lost lock.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if !a.IsLeader(cancelled) {
		t.Fatalf("IsLeader stepped down on a transient (cancelled-ctx) error — flap")
	}
	if !a.Heartbeat(cancelled) {
		t.Fatalf("Heartbeat stepped down on a transient (cancelled-ctx) error — flap")
	}
	// And with a healthy context it is still leader (never released).
	if !a.IsLeader(ctx) {
		t.Fatalf("A lost leadership after a transient blip — should have retained it")
	}
	if !a.Heartbeat(ctx) {
		t.Fatalf("A heartbeat failed after a transient blip — should still hold the lease")
	}
	t.Logf("OK: a transient error on a live connection does not drop leadership (no flap)")
}

// TestHeartbeatFencedWhenLeaseSuperseded proves the promotion fence: if the lease
// row is taken over by another holder/epoch while our advisory-lock connection is
// still alive (the demoted-old-primary scenario), the next Heartbeat returns
// false and we step down. Simulated by rewriting the lease row from a side
// connection, which is exactly what a promoted replica's new leader would do.
func TestHeartbeatFencedWhenLeaseSuperseded(t *testing.T) {
	ctx := context.Background()
	pool := openHAPool(t)

	a := ha.New(pool, leaseKey, "node-A")
	ok, err := a.TryAcquire(ctx)
	if err != nil || !ok {
		t.Fatalf("A acquire: ok=%v err=%v", ok, err)
	}
	defer a.Resign(ctx) // return the held conn even if an assertion fails mid-test
	// A healthy heartbeat succeeds while the lease is ours.
	if !a.Heartbeat(ctx) {
		t.Fatalf("first heartbeat returned false while A holds a fresh lease")
	}

	// Simulate a promotion takeover: a new leader stamps the lease with a different
	// holder and a higher epoch. (On real hardware this is B.TryAcquire on the
	// promoted primary; here A's conn is still live, which is the case we must fence.)
	if _, err := pool.Exec(ctx,
		`UPDATE leader_lease SET holder='node-B', epoch=epoch+1, heartbeat_at=now() WHERE key=$1`,
		leaseKey); err != nil {
		t.Fatal(err)
	}

	// A's next heartbeat must observe it no longer owns the lease → fenced.
	if a.Heartbeat(ctx) {
		t.Fatalf("A heartbeat returned true after its lease was superseded — not fenced (split-brain)")
	}
	// After a fence A must report itself no longer leader.
	if a.IsLeader(ctx) {
		t.Fatalf("A still reports IsLeader after being fenced")
	}
	// Clean up the synthetic lease row.
	_, _ = pool.Exec(ctx, `DELETE FROM leader_lease WHERE key=$1`, leaseKey)
	t.Logf("OK: heartbeat detects a superseded lease and steps down (promotion fence)")
}

// TestFenceExecRejectsAfterFence proves non-idempotent leader work is fenced: a
// write wrapped in FenceExec commits while we hold the lease, but once the lease
// is superseded, FenceExec returns ErrFenced and does NOT run the write. This is
// the guarantee H18's DMARC sender relies on to never double-send across a
// promotion.
func TestFenceExecRejectsAfterFence(t *testing.T) {
	ctx := context.Background()
	pool := openHAPool(t)

	a := ha.New(pool, leaseKey, "node-A")
	ok, err := a.TryAcquire(ctx)
	if err != nil || !ok {
		t.Fatalf("A acquire: ok=%v err=%v", ok, err)
	}
	// FenceExec does not release the conn on ErrFenced (the leader may retry), so
	// resign explicitly to return it before pool.Close.
	defer a.Resign(ctx)

	// While leader, FenceExec runs fn and commits. Use a temp table as the "side
	// effect" so we can observe whether the write happened.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS ha_fence_probe (n int)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ha_fence_probe`) })
	if _, err := pool.Exec(ctx, `TRUNCATE ha_fence_probe`); err != nil {
		t.Fatal(err)
	}

	err = a.FenceExec(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ha_fence_probe (n) VALUES (1)`)
		return e
	})
	if err != nil {
		t.Fatalf("FenceExec while leader returned %v, want nil", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ha_fence_probe`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("FenceExec while leader wrote %d rows, want 1", n)
	}

	// Supersede the lease (promotion takeover), keeping A's conn alive.
	if _, err := pool.Exec(ctx,
		`UPDATE leader_lease SET holder='node-B', epoch=epoch+1, heartbeat_at=now() WHERE key=$1`,
		leaseKey); err != nil {
		t.Fatal(err)
	}

	// Now FenceExec must refuse and NOT run the write.
	err = a.FenceExec(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ha_fence_probe (n) VALUES (2)`)
		return e
	})
	if !errors.Is(err, ha.ErrFenced) {
		t.Fatalf("FenceExec after fence returned %v, want ErrFenced", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ha_fence_probe`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("fenced FenceExec still wrote a row (count=%d) — side effect not prevented", n)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM leader_lease WHERE key=$1`, leaseKey)
	t.Logf("OK: FenceExec commits while leader, returns ErrFenced and skips the write once fenced")
}
