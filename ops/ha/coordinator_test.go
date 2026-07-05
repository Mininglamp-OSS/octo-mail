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

	leaderA := ha.New(poolA, key)
	leaderB := ha.New(poolB, key)
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
