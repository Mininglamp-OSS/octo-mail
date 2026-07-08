package deliverability_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDailyMaintenance proves the H7 fix (#9): the once-per-day warmup
// maintenance advances IPs that met their stage cap, resets sent_today, and runs
// exactly once per UTC day (a second call the same day is a no-op). Without this
// scheduled reset, sent_today never returns to 0 and every warming IP wedges at
// its stage-0 cap, deferring then bouncing all egress-pool deliveries.
func TestDailyMaintenance(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS ip_pools (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, purpose text NOT NULL DEFAULT 'shared')`,
		`CREATE TABLE IF NOT EXISTS ip_addresses (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, pool_id bigint NOT NULL REFERENCES ip_pools(id), ip inet NOT NULL, ptr text, warmup_stage int NOT NULL DEFAULT 0, daily_cap bigint NOT NULL DEFAULT 0, sent_today bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS maintenance_marker (name text PRIMARY KEY, last_run date NOT NULL)`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE ip_addresses, ip_pools RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM maintenance_marker WHERE name='ip_warmup'`); err != nil {
		t.Fatal(err)
	}

	var poolID int64
	if err := pool.QueryRow(ctx, `INSERT INTO ip_pools (name, purpose) VALUES ('p','shared') RETURNING id`).Scan(&poolID); err != nil {
		t.Fatal(err)
	}
	// atCap: stage 0 (cap 50) that sent 50 today → should graduate to stage 1.
	// belowCap: stage 0 that sent 10 → stays at stage 0. Both get sent_today reset.
	// cascade: stage 0 that sent 999999 (exceeds many stages' caps) → must advance
	// EXACTLY one stage (to 1), never skip ahead — guards the per-stage cascade bug.
	var atCap, belowCap, cascade int64
	if err := pool.QueryRow(ctx, `INSERT INTO ip_addresses (pool_id, ip, warmup_stage, sent_today) VALUES ($1,'192.0.2.20',0,50) RETURNING id`, poolID).Scan(&atCap); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO ip_addresses (pool_id, ip, warmup_stage, sent_today) VALUES ($1,'192.0.2.21',0,10) RETURNING id`, poolID).Scan(&belowCap); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO ip_addresses (pool_id, ip, warmup_stage, sent_today) VALUES ($1,'192.0.2.22',0,999999) RETURNING id`, poolID).Scan(&cascade); err != nil {
		t.Fatal(err)
	}

	r := &deliverability.IPRouter{Pool: pool}
	ran, n, err := r.RunDailyMaintenance(ctx)
	if err != nil {
		t.Fatalf("RunDailyMaintenance: %v", err)
	}
	if !ran {
		t.Fatal("first run should have executed")
	}
	if n != 2 {
		t.Fatalf("advanced %d IPs, want 2 (at-cap + cascade)", n)
	}

	stage := func(id int64) int {
		var s int
		if err := pool.QueryRow(ctx, `SELECT warmup_stage FROM ip_addresses WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	sent := func(id int64) int64 {
		var s int64
		if err := pool.QueryRow(ctx, `SELECT sent_today FROM ip_addresses WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if stage(atCap) != 1 {
		t.Fatalf("at-cap IP stage=%d, want 1 (graduated)", stage(atCap))
	}
	if stage(belowCap) != 0 {
		t.Fatalf("below-cap IP stage=%d, want 0 (not graduated)", stage(belowCap))
	}
	if stage(cascade) != 1 {
		t.Fatalf("cascade IP stage=%d, want 1 (exactly one stage, no skip)", stage(cascade))
	}
	if sent(atCap) != 0 || sent(belowCap) != 0 {
		t.Fatalf("sent_today not reset: atCap=%d belowCap=%d", sent(atCap), sent(belowCap))
	}

	// Idempotent within the same UTC day: a second call runs nothing.
	ran2, _, err := r.RunDailyMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ran2 {
		t.Fatal("second same-day run should be a no-op")
	}
	t.Logf("OK: daily maintenance graduated the at-cap IP, reset counters, and is once-per-day")
}
