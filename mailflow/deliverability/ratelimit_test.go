package deliverability_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestSendRateLimiter proves #25-7: the per-tenant outbound rate limiter counts
// each send attempt against a fixed window and blocks once a tenant exceeds its
// cap, isolates tenants from each other, and is disabled (unlimited) when
// MaxPerWindow is 0 — all independent of the egress IP pool.
func TestSendRateLimiter(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenant_send_rate, tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var a, b int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('a') RETURNING id`).Scan(&a)
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('b') RETURNING id`).Scan(&b)

	// A wide window so the whole test lands in one bucket (no flakiness at a
	// window boundary), cap = 3.
	svc := &deliverability.Service{Pool: s.Pool, MaxPerWindow: 3, RateWindow: time.Hour}

	// Tenant A: first 3 sends allowed, the 4th blocked.
	for i := 1; i <= 3; i++ {
		ok, err := svc.AllowSend(ctx, a)
		if err != nil {
			t.Fatalf("AllowSend %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("send %d of 3 blocked, want allowed", i)
		}
	}
	ok, err := svc.AllowSend(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("4th send allowed, want blocked (over cap of 3)")
	}

	// Tenant B is unaffected by A's exhaustion — its own counter is fresh.
	if ok, err := svc.AllowSend(ctx, b); err != nil || !ok {
		t.Fatalf("tenant B send blocked by tenant A's rate usage: ok=%v err=%v", ok, err)
	}

	// Disabled limiter (MaxPerWindow 0): never blocks, no DB write.
	unlimited := &deliverability.Service{Pool: s.Pool, MaxPerWindow: 0}
	for i := 0; i < 100; i++ {
		if ok, err := unlimited.AllowSend(ctx, a); err != nil || !ok {
			t.Fatalf("disabled limiter blocked a send: ok=%v err=%v", ok, err)
		}
	}
	t.Logf("OK: per-tenant fixed-window rate limit blocks over-cap sends, isolates tenants, and is unlimited when disabled")
}

// TestSendRatePrune proves PruneSendRate removes elapsed-window rows while keeping
// the current window, so the counter table stays bounded.
func TestSendRatePrune(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenant_send_rate, tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tid int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('a') RETURNING id`).Scan(&tid)

	svc := &deliverability.Service{Pool: s.Pool, MaxPerWindow: 100, RateWindow: time.Minute}
	// Record a send in the current window.
	if _, err := svc.AllowSend(ctx, tid); err != nil {
		t.Fatal(err)
	}
	// Seed old rows well outside the retained window.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO tenant_send_rate (tenant_id, window_start, count) VALUES
		 ($1, now() - interval '2 hours', 5), ($1, now() - interval '1 day', 9)`, tid); err != nil {
		t.Fatal(err)
	}

	pruned, err := svc.PruneSendRate(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned %d rows, want 2 (the two aged windows)", pruned)
	}
	// The current window's row must survive.
	var remaining int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM tenant_send_rate WHERE tenant_id=$1`, tid).Scan(&remaining)
	if remaining != 1 {
		t.Fatalf("after prune %d rows remain, want 1 (current window)", remaining)
	}
	t.Logf("OK: PruneSendRate removed elapsed windows, kept the current one")
}
