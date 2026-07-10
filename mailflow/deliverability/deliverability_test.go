package deliverability_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// setup opens the store (applies schema, incl. deliverability tables) and seeds
// two tenants. Returns the service and the two tenant ids.
func setup(t *testing.T) (*deliverability.Service, int64, int64) {
	t.Helper()
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE reputation_events, reputation_score, reputation_daily, tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var a, b int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('spammy') RETURNING id`).Scan(&a)
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('clean') RETURNING id`).Scan(&b)
	return &deliverability.Service{Pool: s.Pool}, a, b
}

// TestReputationIsolation is the P5 crown proof: tenant A generates complaints to
// gmail.com and gets auto-paused FOR gmail.com; tenant B, sending to the same
// remote, is completely unaffected. One spammy tenant cannot poison another's
// (or the platform's) ability to send.
func TestReputationIsolation(t *testing.T) {
	ctx := context.Background()
	svc, tenantA, tenantB := setup(t)
	const remote = "gmail.com"

	// Both tenants send a healthy volume to the same remote.
	for i := 0; i < 50; i++ {
		if err := svc.RecordSent(ctx, tenantA, remote); err != nil {
			t.Fatal(err)
		}
		if err := svc.RecordSent(ctx, tenantB, remote); err != nil {
			t.Fatal(err)
		}
	}

	// Baseline: both allowed.
	mustAllow(t, svc, tenantA, remote, true)
	mustAllow(t, svc, tenantB, remote, true)

	// Tenant A racks up complaints past the 1% threshold (>0.5 on 50 sends).
	for i := 0; i < 3; i++ {
		if err := svc.RecordEvent(ctx, tenantA, 0, deliverability.KindComplaint, remote, 0); err != nil {
			t.Fatal(err)
		}
	}

	// THE INVARIANT: A is now paused for gmail.com; B is untouched.
	mustAllow(t, svc, tenantA, remote, false)
	mustAllow(t, svc, tenantB, remote, true)

	// A is only paused for gmail.com — sending elsewhere still works.
	mustAllow(t, svc, tenantA, "outlook.com", true)

	t.Logf("OK: spammy tenant A paused for gmail.com; clean tenant B unaffected; A still ok for outlook.com")
}

// TestVERPAttribution proves bounces/complaints route back to the exact sending
// tenant via the VERP return-path token — no cross-tenant misattribution.
func TestVERPAttribution(t *testing.T) {
	ctx := context.Background()
	svc, tenantA, tenantB := setup(t)

	// Build a VERP return-path for a message tenant A sent, decode it, and record
	// the resulting complaint against the decoded tenant.
	token := deliverability.VERPToken(tenantA, 12345)
	gotTenant, gotMsg, ok := deliverability.ParseVERP(token)
	if !ok || gotTenant != tenantA || gotMsg != 12345 {
		t.Fatalf("VERP round-trip failed: token=%q -> tenant=%d msg=%d ok=%v", token, gotTenant, gotMsg, ok)
	}

	// A complaint arrives addressed to the VERP token -> attributed to tenant A.
	if err := svc.RecordEvent(ctx, gotTenant, 0, deliverability.KindComplaint, "yahoo.com", 0); err != nil {
		t.Fatal(err)
	}

	// Verify the event landed on A, not B.
	var aCount, bCount int
	svc.Pool.QueryRow(ctx, `SELECT count(*) FROM reputation_events WHERE tenant_id=$1`, tenantA).Scan(&aCount)
	svc.Pool.QueryRow(ctx, `SELECT count(*) FROM reputation_events WHERE tenant_id=$1`, tenantB).Scan(&bCount)
	if aCount != 1 || bCount != 0 {
		t.Fatalf("VERP misattribution: A=%d B=%d, want A=1 B=0", aCount, bCount)
	}
	t.Logf("OK: complaint via VERP token attributed to sending tenant A (A=%d, B=%d)", aCount, bCount)
}

// TestAutoUnpauseRecovered proves the #22-2 / #33 decay path: a domain auto-paused
// on a bad window is automatically unpaused once its recent windowed rates recover
// — no manual DB edit. Recovery here is modeled by aging the bad events out of the
// window (moving the bad day outside DefaultWindow) and adding fresh clean volume.
func TestAutoUnpauseRecovered(t *testing.T) {
	ctx := context.Background()
	svc, tenantA, _ := setup(t)
	const remote = "gmail.com"

	// Healthy volume, then enough complaints to breach and pause (today's window).
	for i := 0; i < 50; i++ {
		if err := svc.RecordSent(ctx, tenantA, remote); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := svc.RecordEvent(ctx, tenantA, 0, deliverability.KindComplaint, remote, 0); err != nil {
			t.Fatal(err)
		}
	}
	mustAllow(t, svc, tenantA, remote, false) // paused

	// Auto-unpause with the bad events still in-window must NOT unpause it.
	if n, err := svc.UnpauseRecovered(ctx); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("unpaused %d while still breaching in-window; want 0", n)
	}
	mustAllow(t, svc, tenantA, remote, false)

	// Age the breach out of the window: move all of this (tenant, domain)'s daily
	// buckets to well before DefaultWindow. Now the recent window is empty →
	// recovered (bad history has aged out). Also age paused_at past MinPauseDwell so
	// the dwell floor doesn't hold it.
	if _, err := svc.Pool.Exec(ctx,
		`UPDATE reputation_daily SET day = (now() AT TIME ZONE 'utc')::date - 60
		 WHERE tenant_id=$1 AND remote_domain=$2`, tenantA, remote); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Pool.Exec(ctx,
		`UPDATE reputation_score SET paused_at = now() - interval '48 hours'
		 WHERE tenant_id=$1 AND remote_domain=$2`, tenantA, remote); err != nil {
		t.Fatal(err)
	}
	n, err := svc.UnpauseRecovered(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("UnpauseRecovered unpaused %d, want 1 (window aged out the breach)", n)
	}
	mustAllow(t, svc, tenantA, remote, true) // recovered
	t.Logf("OK: auto-paused domain auto-unpaused once the bad window aged out (decay path, #33)")
}

func mustAllow(t *testing.T, svc *deliverability.Service, tenantID int64, remote string, want bool) {
	t.Helper()
	r, err := svc.Gate(context.Background(), tenantID, remote)
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed != want {
		t.Fatalf("Gate(tenant=%d, %s).Allowed = %v (%s), want %v", tenantID, remote, r.Allowed, r.Reason, want)
	}
}
