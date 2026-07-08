package deliverability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoSourceIP means no assigned IP has remaining daily capacity for this
// tenant right now (all warmup caps reached). The caller should defer (retry
// later) rather than send from an unwarmed or foreign IP.
var ErrNoSourceIP = errors.New("no source IP with remaining daily capacity")

// IPRouter selects an outbound source IP for a tenant, enforcing per-IP daily
// caps and warmup ramps so that (a) a warming dedicated IP never exceeds its
// stage cap, and (b) a bad tenant on a dedicated pool cannot borrow a healthy
// shared IP. Each successful lease increments sent_today atomically under the
// row lock, so concurrent deliverers on different nodes never over-send a
// capped IP.
type IPRouter struct {
	Pool *pgxpool.Pool
}

// warmupCaps is the classic ~6-week ramp (messages/day) indexed by warmup_stage.
// Stage 0 is "unwarmed" (small); the last entry is treated as "fully warmed"
// (uncapped when daily_cap is 0). Operators can override per-IP via daily_cap.
var warmupCaps = []int64{50, 100, 500, 1000, 5000, 10000, 20000, 50000, 100000}

// WarmupCapForStage returns the messages/day cap implied by a warmup stage.
func WarmupCapForStage(stage int) int64 {
	if stage < 0 {
		stage = 0
	}
	if stage >= len(warmupCaps) {
		return 0 // fully warmed → uncapped (subject to explicit daily_cap)
	}
	return warmupCaps[stage]
}

// LeasedIP is a selected source IP with its PTR (for EHLO/HELO identity).
type LeasedIP struct {
	ID  int64
	IP  net.IP
	PTR string
}

// LeaseSourceIP picks and reserves one source IP for the tenant's send. It
// prefers the tenant's dedicated pool, then any assigned shared pool, choosing
// the IP with the most remaining headroom (least-loaded), and atomically bumps
// sent_today. The effective cap is min(explicit daily_cap, warmup-stage cap),
// where 0 means uncapped. Returns ErrNoSourceIP if every candidate is at cap.
func (r *IPRouter) LeaseSourceIP(ctx context.Context, tenantID int64) (LeasedIP, error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return LeasedIP{}, err
	}
	defer tx.Rollback(ctx)

	// Candidate IPs in pools assigned to this tenant, dedicated pools first,
	// then by remaining headroom. Locked FOR UPDATE SKIP LOCKED so parallel
	// deliverers pick different rows instead of serializing on the hottest IP.
	rows, err := tx.Query(ctx, `
		SELECT a.id, a.ip::text, a.ptr, a.warmup_stage, a.daily_cap, a.sent_today
		FROM ip_addresses a
		JOIN tenant_ip_assignment t ON t.pool_id = a.pool_id
		JOIN ip_pools p ON p.id = a.pool_id
		WHERE t.tenant_id = $1 AND p.purpose <> 'penalty'
		ORDER BY t.dedicated DESC, a.sent_today ASC
		FOR UPDATE OF a SKIP LOCKED`, tenantID)
	if err != nil {
		return LeasedIP{}, err
	}
	type cand struct {
		id        int64
		ip        net.IP
		ptr       string
		stage     int
		dailyCap  int64
		sentToday int64
	}
	var chosen *cand
	for rows.Next() {
		var c cand
		var ipStr string
		var ptr *string
		if err := rows.Scan(&c.id, &ipStr, &ptr, &c.stage, &c.dailyCap, &c.sentToday); err != nil {
			rows.Close()
			return LeasedIP{}, err
		}
		if ptr != nil {
			c.ptr = *ptr
		}
		if i := strings.IndexByte(ipStr, '/'); i >= 0 {
			ipStr = ipStr[:i]
		}
		c.ip = net.ParseIP(ipStr)
		// Effective cap = min of explicit daily_cap and warmup-stage cap (0=uncapped).
		eff := effectiveCap(c.dailyCap, WarmupCapForStage(c.stage))
		if eff != 0 && c.sentToday >= eff {
			continue // at cap
		}
		cc := c
		chosen = &cc
		break // rows are already ordered dedicated-first, least-loaded-first
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return LeasedIP{}, err
	}
	if chosen == nil {
		return LeasedIP{}, ErrNoSourceIP
	}

	if _, err := tx.Exec(ctx, `UPDATE ip_addresses SET sent_today = sent_today + 1 WHERE id = $1`, chosen.id); err != nil {
		return LeasedIP{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LeasedIP{}, err
	}
	return LeasedIP{ID: chosen.id, IP: chosen.ip, PTR: chosen.ptr}, nil
}

// effectiveCap returns the binding cap given an explicit daily_cap and a
// warmup-stage cap; 0 means uncapped for either input.
func effectiveCap(explicit, warmup int64) int64 {
	switch {
	case explicit == 0:
		return warmup
	case warmup == 0:
		return explicit
	case explicit < warmup:
		return explicit
	default:
		return warmup
	}
}

// ResetDailyCounters zeroes sent_today for all IPs (run at the day boundary).
func (r *IPRouter) ResetDailyCounters(ctx context.Context) error {
	_, err := r.Pool.Exec(ctx, `UPDATE ip_addresses SET sent_today = 0`)
	return err
}

// RunDailyMaintenance performs the once-per-day warmup advance + daily-counter
// reset, but only if it has not already run today (UTC). The whole operation —
// claiming the day via the maintenance_marker row, advancing warmup, and
// resetting sent_today — runs in ONE transaction, so a crash/leadership loss
// mid-run rolls back the day-claim too (the marker is never left saying "done"
// while the reset didn't happen). Safe to call on a frequent leader tick or from
// a freshly-elected leader after failover. Returns (ran, advancedIPs, err); ran
// is false when today was already done.
func (r *IPRouter) RunDailyMaintenance(ctx context.Context) (ran bool, advanced int64, err error) {
	err = pgx.BeginFunc(ctx, r.Pool, func(tx pgx.Tx) error {
		// Atomically claim today. INSERT the marker if absent, else bump it only
		// when behind today's date; RETURNING yields a row only when this txn won
		// the day. A losing racer blocks on the row lock, re-evaluates the WHERE
		// against the committed date, matches nothing → ErrNoRows.
		var claimed bool
		cerr := tx.QueryRow(ctx, `
			INSERT INTO maintenance_marker (name, last_run)
			VALUES ('ip_warmup', (now() AT TIME ZONE 'utc')::date)
			ON CONFLICT (name) DO UPDATE SET last_run = EXCLUDED.last_run
			WHERE maintenance_marker.last_run < (now() AT TIME ZONE 'utc')::date
			RETURNING true`).Scan(&claimed)
		if errors.Is(cerr, pgx.ErrNoRows) {
			return nil // already ran today; ran stays false
		}
		if cerr != nil {
			return cerr
		}
		n, aerr := advanceWarmupDue(ctx, tx)
		if aerr != nil {
			return aerr
		}
		if _, rerr := tx.Exec(ctx, `UPDATE ip_addresses SET sent_today = 0`); rerr != nil {
			return rerr
		}
		ran, advanced = true, n
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	return ran, advanced, nil
}

// AdvanceWarmup bumps an IP's warmup_stage by one (run daily for warming IPs
// that met their cap), widening tomorrow's allowance until fully warmed.
func (r *IPRouter) AdvanceWarmup(ctx context.Context, ipID int64) error {
	tag, err := r.Pool.Exec(ctx, `UPDATE ip_addresses SET warmup_stage = warmup_stage + 1 WHERE id = $1`, ipID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no ip_address id %d", ipID)
	}
	return nil
}

// AdvanceWarmupDue bumps warmup_stage by exactly one for every still-warming IP
// that reached its current stage's cap today, so tomorrow's allowance widens. An
// IP that did not hit its cap is left where it is (not ready to graduate).
// Fully-warmed IPs (past the ramp table) are untouched. Returns the number
// advanced. Intended to run once per day, leader-gated, right before
// ResetDailyCounters.
func (r *IPRouter) AdvanceWarmupDue(ctx context.Context) (int64, error) {
	return advanceWarmupDue(ctx, r.Pool)
}

// execer is satisfied by both *pgxpool.Pool and pgx.Tx.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func advanceWarmupDue(ctx context.Context, db execer) (int64, error) {
	// Single set-based UPDATE evaluated against each IP's CURRENT stage in one
	// pass, so no IP is advanced more than one stage per call (a per-stage loop
	// would cascade: bumping 0→1 then re-examining the same row at stage 1). The
	// per-stage cap is a CASE built from the ramp table (still the single source
	// of truth); rows at/after the last stage have no CASE arm (ELSE NULL) and
	// never match, since `sent_today >= NULL` is never true.
	var caseArms strings.Builder
	args := make([]any, 0, len(warmupCaps))
	for stage := 0; stage < len(warmupCaps); stage++ {
		args = append(args, warmupCaps[stage])
		fmt.Fprintf(&caseArms, " WHEN %d THEN $%d::bigint", stage, len(args))
	}
	q := `UPDATE ip_addresses SET warmup_stage = warmup_stage + 1
	      WHERE sent_today >= CASE warmup_stage` + caseArms.String() + ` ELSE NULL END`
	tag, err := db.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// EvictToPenalty moves an IP into the penalty pool (e.g. after a complaint
// spike), removing it from tenant selection without deleting its history.
func (r *IPRouter) EvictToPenalty(ctx context.Context, ipID int64) error {
	_, err := r.Pool.Exec(ctx, `
		UPDATE ip_addresses SET pool_id = (
			SELECT id FROM ip_pools WHERE purpose='penalty' ORDER BY id LIMIT 1
		) WHERE id = $1`, ipID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("no penalty pool configured")
	}
	return err
}
