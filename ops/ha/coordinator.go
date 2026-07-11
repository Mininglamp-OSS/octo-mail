package ha

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Coordinator turns the single-leader primitive into automatic failover
// orchestration: it continuously campaigns for leadership on an interval, and
// runs registered singleton work ONLY while it holds leadership. When the leader
// crashes, PostgreSQL releases the advisory lock; a standby's next campaign wins
// and it begins running the work — so the *workload* fails over automatically,
// not just the lock. This is the in-process automation an external orchestrator
// (Patroni/repmgr) would otherwise provide for cluster singletons.
type Coordinator struct {
	leader   *Leader
	interval time.Duration

	// wasLeader is the campaign loop's cached leadership view. Written only by the
	// Run goroutine; read by IsLeader from other goroutines (hence atomic).
	wasLeader atomic.Bool

	// tickRunning single-flights the async Tick: the campaign loop launches Tick in
	// a background goroutine (so a long Tick never blocks lease heartbeat / leader
	// re-probe), and skips launching a new one while the previous is still running.
	tickRunning atomic.Bool
	// tickWG tracks in-flight Tick goroutines so Run can await them on shutdown.
	tickWG sync.WaitGroup

	// OnElected is invoked once each time this node transitions to leader. Use it
	// to (re)start singleton work. It must return promptly; long work belongs in
	// goroutines it launches, guarded by IsLeader.
	OnElected func(context.Context)
	// OnLost is invoked once each time this node transitions out of leadership
	// (crash-detected or resigned). Use it to stop singleton work.
	OnLost func()
	// Tick, if set, is invoked on every campaign interval while this node is the
	// leader — the natural place to run periodic singleton jobs (drains, report
	// scheduling) that must run on exactly one node.
	Tick func(context.Context)
}

// NewCoordinator builds a Coordinator that campaigns on the given lock key every
// interval.
func NewCoordinator(leader *Leader, interval time.Duration) *Coordinator {
	return &Coordinator{leader: leader, interval: interval}
}

// Run campaigns until ctx is cancelled. It fires OnElected/OnLost on leadership
// transitions and Tick on each interval while leader. On return it resigns any
// held leadership so a standby can take over immediately.
func (c *Coordinator) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	defer func() {
		// Wait for any in-flight async Tick to finish before resigning, so a
		// singleton job isn't torn down mid-write on shutdown.
		c.tickWG.Wait()
		if c.wasLeader.Swap(false) && c.OnLost != nil {
			c.OnLost()
		}
		// Best-effort resign so a standby need not wait for TCP keepalive to
		// notice our departure.
		_ = c.leader.Resign(context.Background())
	}()

	campaign := func() {
		// wasLeader is written only here (the Run goroutine); load once, compute
		// the new state, publish once.
		prev := c.wasLeader.Load()
		now := prev
		if now {
			switch {
			case !c.leader.IsLeader(ctx):
				// Lost the advisory lock (our backend crashed/was terminated). This is
				// the fast same-primary failover path: fall through to re-acquire on
				// THIS tick so a standby-or-self takes over without delay.
				now = false
			case !c.leader.Heartbeat(ctx):
				// Fenced: the replicated lease was taken over (a promotion left us a
				// stale/demoted primary) or our heartbeat write failed on a now
				// read-only backend. Step DOWN this tick — fire OnLost and do NOT
				// re-acquire on the same tick, or we'd silently re-stamp the lease and
				// mask the fence. The next tick re-campaigns cleanly (and the
				// pg_is_in_recovery gate keeps a demoted node from re-winning).
				c.wasLeader.Store(false)
				if c.OnLost != nil {
					c.OnLost()
				}
				return
			}
		}
		if !now {
			if ok, err := c.leader.TryAcquire(ctx); err == nil && ok {
				now = true
			}
		}
		c.wasLeader.Store(now)
		switch {
		case now && !prev:
			if c.OnElected != nil {
				c.OnElected(ctx)
			}
		case !now && prev:
			if c.OnLost != nil {
				c.OnLost()
			}
		}
		if now && c.Tick != nil {
			c.launchTick(ctx)
		}
	}

	campaign() // campaign immediately rather than waiting a full interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			campaign()
		}
	}
}

// launchTick runs Tick in a background goroutine so a long-running singleton job
// never blocks the campaign loop (which must keep renewing the lease and
// re-probing leadership on schedule — a Tick that ran inline could defer the
// heartbeat past the lease horizon and self-induce a fence). It single-flights:
// if the previous Tick is still running, this campaign skips launching a new one
// (ticks coalesce rather than pile up). The goroutine re-checks cached leadership
// before running, so a Tick launched just as leadership is lost is a no-op.
func (c *Coordinator) launchTick(ctx context.Context) {
	if !c.tickRunning.CompareAndSwap(false, true) {
		return // previous Tick still in flight; skip this interval
	}
	c.tickWG.Add(1)
	go func() {
		defer c.tickWG.Done()
		defer c.tickRunning.Store(false)
		// Guard against a race where leadership was lost between the campaign
		// decision and this goroutine starting; the cached view is authoritative.
		if !c.wasLeader.Load() || ctx.Err() != nil {
			return
		}
		c.Tick(ctx)
	}()
}

// IsLeader reports whether this coordinator currently holds leadership. It reads
// the campaign loop's cached view rather than probing the connection, so it is
// consistent with the OnElected/OnLost callbacks and does not race the Run
// goroutine on the underlying Leader connection.
func (c *Coordinator) IsLeader() bool { return c.wasLeader.Load() }

// Leader returns the underlying Leader, so a Tick job can reach FenceExec/Epoch
// to run non-idempotent singleton work under the promotion fence. Only meaningful
// to call from within Tick (i.e. while this node holds leadership); the campaign
// goroutine owns the Leader's connection, and FenceExec deliberately borrows a
// fresh pooled connection so it is safe to call concurrently with the campaign.
func (c *Coordinator) Leader() *Leader { return c.leader }
