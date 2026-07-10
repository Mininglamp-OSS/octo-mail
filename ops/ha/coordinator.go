package ha

import (
	"context"
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
			c.Tick(ctx)
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
