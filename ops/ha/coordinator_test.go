package ha_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/ops/ha"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCoordinatorAutoFailover proves automatic *workload* failover, not just lock
// handoff: two Coordinators contend; only the leader runs the singleton job
// (Tick). When the leader's session is killed (crash), the standby is elected and
// begins running the job automatically, with no manual intervention.
func TestCoordinatorAutoFailover(t *testing.T) {
	ctx := context.Background()

	poolA, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := poolA.Ping(ctx); err != nil {
		poolA.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	defer poolA.Close()
	poolB, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()
	// A side connection used to kill the current leader's backend, forcing PG to
	// release the advisory lock (the reliable crash simulation).
	killer, err := pgxpool.New(ctx, haDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer killer.Close()

	const key = int64(0x6661696c32) // "fail2"

	// leader_lease must exist for TryAcquire's lease claim; the raw pools here
	// don't run the full schema. Clean any leftover row for this key.
	ensureLeaseSchema(t, poolA)
	if _, err := poolA.Exec(ctx, `DELETE FROM leader_lease WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}

	leaderA := ha.New(poolA, key, "node-A")
	leaderB := ha.New(poolB, key, "node-B")
	var ticksA, ticksB atomic.Int64
	var electedA, electedB atomic.Int64
	coA := ha.NewCoordinator(leaderA, 50*time.Millisecond)
	coA.OnElected = func(context.Context) { electedA.Add(1) }
	coA.Tick = func(context.Context) { ticksA.Add(1) }
	coB := ha.NewCoordinator(leaderB, 50*time.Millisecond)
	coB.OnElected = func(context.Context) { electedB.Add(1) }
	coB.Tick = func(context.Context) { ticksB.Add(1) }

	ctxA, cancelA := context.WithCancel(ctx)
	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelA()
	defer cancelB()
	go coA.Run(ctxA)
	go coB.Run(ctxB)

	// Let leadership settle and the leader accrue ticks.
	time.Sleep(400 * time.Millisecond)

	// Exactly one node should have been elected and be ticking.
	aLead := electedA.Load() > 0
	bLead := electedB.Load() > 0
	if aLead == bLead {
		t.Fatalf("expected exactly one leader, got electedA=%d electedB=%d", electedA.Load(), electedB.Load())
	}
	leaderTicks, followerTicks := &ticksA, &ticksB
	leaderNode := leaderA
	followerElected, followerTicks2 := &electedB, &ticksB
	stopLeader := cancelA
	if bLead {
		leaderTicks, followerTicks = &ticksB, &ticksA
		leaderNode = leaderB
		followerElected, followerTicks2 = &electedA, &ticksA
		stopLeader = cancelB
	}
	if leaderTicks.Load() == 0 {
		t.Fatalf("leader never ran the singleton job")
	}
	if followerTicks.Load() != 0 {
		t.Fatalf("follower ran the singleton job (%d) — not a singleton!", followerTicks.Load())
	}

	// Crash the leader: stop its Coordinator (the process is gone) AND terminate
	// its PostgreSQL backend, which releases the advisory lock. Only the surviving
	// node still campaigns, so the takeover we observe is a genuine handoff.
	pid := leaderNode.BackendPID()
	if pid == 0 {
		t.Fatalf("leader has no backend pid")
	}
	stopLeader()
	if _, err := killer.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatalf("terminate leader backend: %v", err)
	}

	// The surviving node must be elected and start ticking automatically.
	before := followerTicks2.Load()
	elected := false
	for i := 0; i < 200; i++ { // up to ~10s
		if followerElected.Load() > 0 && followerTicks2.Load() > before {
			elected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !elected {
		t.Fatalf("surviving node did not take over the singleton workload after leader crash (elected=%d ticksDelta=%d)",
			followerElected.Load(), followerTicks2.Load()-before)
	}

	t.Logf("OK: single leader ran the singleton job; on leader backend crash the standby was elected and resumed the job automatically")
}

// TestCoordinatorStepsDownWhenFenced proves the promotion step-down is OBSERVED,
// not masked: when the leader's lease is taken over out-of-band (a promoted
// replica's new leader stamps the lease row with a different holder), the
// leader's next campaign tick must see Heartbeat fail and fire OnLost — it must
// NOT silently re-acquire on the SAME tick and skip the transition. (On a real
// demoted replica the pg_is_in_recovery gate then keeps it down durably; on this
// single healthy DB the node is still a valid primary and legitimately re-wins on
// a later tick, so the fence surfaces as an OnLost→OnElected cycle rather than a
// masked no-op — that cycle is exactly what the fix guarantees.)
func TestCoordinatorStepsDownWhenFenced(t *testing.T) {
	ctx := context.Background()
	pool := openHAPool(t) // ensures schema + clean lease row for leaseKey

	leader := ha.New(pool, leaseKey, "node-A")
	var ticks, lost, elected atomic.Int64
	co := ha.NewCoordinator(leader, 40*time.Millisecond)
	co.OnElected = func(context.Context) { elected.Add(1) }
	co.OnLost = func() { lost.Add(1) }
	co.Tick = func(context.Context) { ticks.Add(1) }

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go co.Run(runCtx)

	// Wait until it has become leader and is ticking.
	up := false
	for i := 0; i < 100; i++ {
		if co.IsLeader() && ticks.Load() > 0 {
			up = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatalf("coordinator never became leader/ticking")
	}
	if elected.Load() != 1 {
		t.Fatalf("OnElected fired %d times before fence, want 1", elected.Load())
	}

	// Simulate a promotion takeover: rewrite the lease row to a different holder
	// with a higher epoch (what a promoted replica's new leader would commit).
	if _, err := pool.Exec(ctx,
		`UPDATE leader_lease SET holder='node-B', epoch=epoch+1, heartbeat_at=now() WHERE key=$1`,
		leaseKey); err != nil {
		t.Fatal(err)
	}

	// The coordinator must OBSERVE the fence: OnLost fires. With the masked-fence
	// bug (same-tick re-acquire), lost would stay 0 forever.
	observed := false
	for i := 0; i < 100; i++ {
		if lost.Load() > 0 {
			observed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !observed {
		t.Fatalf("coordinator never fired OnLost after its lease was taken over — fence masked by same-tick re-acquire")
	}
	t.Logf("OK: coordinator observed the lease takeover and fired OnLost (fence not masked; lost=%d)", lost.Load())
}
