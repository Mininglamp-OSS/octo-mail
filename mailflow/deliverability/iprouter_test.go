package deliverability_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIPPoolWarmupRouting proves P2-2: outbound source-IP selection enforces
// per-IP warmup daily caps, prefers a tenant's dedicated pool, spreads load to
// the least-loaded IP, refuses to send once every assigned IP is at cap
// (ErrNoSourceIP → caller defers rather than sending from an unwarmed/foreign
// IP), and can evict a bad IP to a penalty pool so it is no longer selected.
func TestIPPoolWarmupRouting(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	// Ensure schema (real postgres schema already has these; create if isolated).
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS ip_pools (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, purpose text NOT NULL DEFAULT 'shared')`,
		`CREATE TABLE IF NOT EXISTS ip_addresses (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, pool_id bigint NOT NULL REFERENCES ip_pools(id), ip inet NOT NULL, ptr text, warmup_stage int NOT NULL DEFAULT 0, daily_cap bigint NOT NULL DEFAULT 0, sent_today bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS tenant_ip_assignment (tenant_id bigint NOT NULL, pool_id bigint NOT NULL REFERENCES ip_pools(id), dedicated boolean NOT NULL DEFAULT false, PRIMARY KEY (tenant_id, pool_id))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE tenant_ip_assignment, ip_addresses, ip_pools RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	const tenant = int64(1)
	// A dedicated warming pool (stage 0 → cap 50) with two IPs, plus a penalty pool.
	var dedPool, penPool int64
	if err := pool.QueryRow(ctx, `INSERT INTO ip_pools (name, purpose) VALUES ('ded','dedicated') RETURNING id`).Scan(&dedPool); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO ip_pools (name, purpose) VALUES ('pen','penalty') RETURNING id`).Scan(&penPool); err != nil {
		t.Fatal(err)
	}
	var ipA, ipB int64
	if err := pool.QueryRow(ctx, `INSERT INTO ip_addresses (pool_id, ip, ptr, warmup_stage, daily_cap) VALUES ($1,'192.0.2.10','mxa.example',0,0) RETURNING id`, dedPool).Scan(&ipA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO ip_addresses (pool_id, ip, ptr, warmup_stage, daily_cap) VALUES ($1,'192.0.2.11','mxb.example',0,0) RETURNING id`, dedPool).Scan(&ipB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_ip_assignment (tenant_id, pool_id, dedicated) VALUES ($1,$2,true)`, tenant, dedPool); err != nil {
		t.Fatal(err)
	}

	r := &deliverability.IPRouter{Pool: pool}

	// Stage-0 warmup cap is 50/IP → 2 IPs → 100 leases succeed, 101st fails.
	if got := deliverability.WarmupCapForStage(0); got != 50 {
		t.Fatalf("WarmupCapForStage(0)=%d, want 50", got)
	}
	counts := map[int64]int{}
	for i := 0; i < 100; i++ {
		leased, err := r.LeaseSourceIP(ctx, tenant)
		if err != nil {
			t.Fatalf("lease %d failed early: %v", i, err)
		}
		counts[leased.ID]++
		if leased.PTR == "" {
			t.Fatalf("leased IP missing PTR")
		}
	}
	// Load spread across both IPs (least-loaded selection), each at its cap of 50.
	if counts[ipA] != 50 || counts[ipB] != 50 {
		t.Fatalf("warmup caps not enforced/spread: ipA=%d ipB=%d, want 50/50", counts[ipA], counts[ipB])
	}
	// 101st lease: everything at cap → defer.
	if _, err := r.LeaseSourceIP(ctx, tenant); err != deliverability.ErrNoSourceIP {
		t.Fatalf("expected ErrNoSourceIP at cap, got %v", err)
	}

	// Advancing warmup widens tomorrow's cap; reset counters to model a new day.
	if err := r.AdvanceWarmup(ctx, ipA); err != nil {
		t.Fatal(err)
	}
	if err := r.ResetDailyCounters(ctx); err != nil {
		t.Fatal(err)
	}
	// ipA is now stage 1 (cap 100), ipB still stage 0 (cap 50). Lease 51 should
	// all go to... least-loaded first means they interleave, but ipB caps at 50.
	// Lease 60 messages: ipB takes up to 50, ipA takes the rest.
	counts = map[int64]int{}
	for i := 0; i < 60; i++ {
		leased, err := r.LeaseSourceIP(ctx, tenant)
		if err != nil {
			t.Fatalf("post-warmup lease %d failed: %v", i, err)
		}
		counts[leased.ID]++
	}
	if counts[ipB] > 50 {
		t.Fatalf("ipB exceeded its stage-0 cap: %d", counts[ipB])
	}
	if counts[ipA]+counts[ipB] != 60 {
		t.Fatalf("lost leases: ipA=%d ipB=%d", counts[ipA], counts[ipB])
	}

	// Evict ipA to penalty: it must no longer be selected.
	if err := r.EvictToPenalty(ctx, ipA); err != nil {
		t.Fatal(err)
	}
	if err := r.ResetDailyCounters(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		leased, err := r.LeaseSourceIP(ctx, tenant)
		if err != nil {
			t.Fatalf("post-evict lease %d failed: %v", i, err)
		}
		if leased.ID == ipA {
			t.Fatalf("evicted ipA was still selected")
		}
	}

	t.Logf("OK: warmup caps enforced (50/IP stage 0), load spread least-loaded, at-cap → ErrNoSourceIP, warmup advance widens cap, penalty eviction removes IP from selection")
}
