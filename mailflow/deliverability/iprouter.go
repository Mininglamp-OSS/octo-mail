package deliverability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
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
