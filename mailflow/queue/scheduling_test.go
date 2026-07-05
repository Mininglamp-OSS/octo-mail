package queue_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestExponentialBackoff proves the retry delay grows per attempt (base, 2×, 4×)
// instead of a flat interval: after the Nth failure next_attempt is roughly
// base·2^(N-1) in the future (within jitter). It drives the worker's real
// reschedule path against a Deliverer that always fails.
func TestExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "bref", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	base := 10 * time.Second
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1, Backoff: base,
		Deliver: func(ctx context.Context, m queue.Msg) error { return errors.New("boom") },
	}

	// Attempt 1: reschedule ~base ahead. Force the row due each round so the
	// worker re-claims it (bumping attempts) and we can read the growing delay.
	prev := time.Duration(0)
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		var delaySecs float64
		if err := p.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM (next_attempt - now())) FROM queue WHERE id=$1`, id).Scan(&delaySecs); err != nil {
			t.Fatal(err)
		}
		d := time.Duration(delaySecs * float64(time.Second))
		want := base
		for i := 1; i < attempt; i++ {
			want *= 2
		}
		// Allow ±25% for jitter + clock.
		lo, hi := time.Duration(float64(want)*0.7), time.Duration(float64(want)*1.3)
		if d < lo || d > hi {
			t.Fatalf("attempt %d: backoff %v out of range [%v,%v] (want ~%v)", attempt, d, lo, hi, want)
		}
		if attempt > 1 && d < prev {
			t.Fatalf("attempt %d: backoff %v did not grow past previous %v", attempt, d, prev)
		}
		prev = d
	}

	// last_error is recorded.
	var lastErr string
	_ = p.QueryRow(ctx, `SELECT COALESCE(last_error,'') FROM queue WHERE id=$1`, id).Scan(&lastErr)
	if lastErr != "boom" {
		t.Fatalf("last_error=%q, want %q", lastErr, "boom")
	}
}

// TestHoldSkipsDelivery proves a held message is never claimed, and unholding it
// makes it deliverable again.
func TestHoldSkipsDelivery(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "bref", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	var delivered atomic.Int64
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 10,
		Deliver: func(ctx context.Context, m queue.Msg) error { delivered.Add(1); return nil },
	}

	// Hold it, then a worker tick must claim nothing.
	if n, err := queue.HoldSet(ctx, p, queue.Filter{IDs: []int64{id}}, true); err != nil || n != 1 {
		t.Fatalf("HoldSet: n=%d err=%v", n, err)
	}
	if n, err := w.RunOnce(ctx); err != nil || n != 0 {
		t.Fatalf("held message was claimed: n=%d err=%v", n, err)
	}
	if got := delivered.Load(); got != 0 {
		t.Fatalf("delivered %d while held; want 0", got)
	}

	// Unhold, then it delivers.
	if n, err := queue.HoldSet(ctx, p, queue.Filter{IDs: []int64{id}}, false); err != nil || n != 1 {
		t.Fatalf("unhold: n=%d err=%v", n, err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := delivered.Load(); got != 1 {
		t.Fatalf("delivered %d after unhold; want 1", got)
	}
}

// TestAdminKickAndDrop proves Kick makes a not-yet-due message due immediately,
// and Drop removes messages silently (no retired row).
func TestAdminKickAndDrop(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// A message scheduled far in the future (FUTURERELEASE-style).
	future := time.Now().Add(24 * time.Hour)
	kickID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "b1", Size: 10, NotBefore: future,
	})
	if err != nil {
		t.Fatal(err)
	}

	var delivered atomic.Int64
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 10,
		Deliver: func(ctx context.Context, m queue.Msg) error { delivered.Add(1); return nil },
	}
	// Not due yet.
	if n, _ := w.RunOnce(ctx); n != 0 {
		t.Fatalf("future message claimed early: %d", n)
	}
	// Kick → due now → delivered.
	if n, err := queue.Kick(ctx, p, queue.Filter{IDs: []int64{kickID}}); err != nil || n != 1 {
		t.Fatalf("Kick: n=%d err=%v", n, err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != 1 {
		t.Fatalf("kicked message not delivered")
	}

	// Drop: enqueue another and drop it — gone with no retired row.
	dropID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "b2", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := queue.Drop(ctx, p, queue.Filter{IDs: []int64{dropID}}); err != nil || n != 1 {
		t.Fatalf("Drop: n=%d err=%v", n, err)
	}
	var live int
	var kind string
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, dropID).Scan(&live)
	_ = p.QueryRow(ctx, `SELECT kind FROM queue_log WHERE queue_id=$1 AND keep_until IS NOT NULL`, dropID).Scan(&kind)
	if live != 0 || kind != "dropped" {
		t.Fatalf("after Drop: live=%d terminal=%q, want 0/dropped (silent cancel, audit-logged, no DSN)", live, kind)
	}
}

// TestAdminFailSendsDSN proves Fail removes a message, records a retired failure,
// and fires the onFailed (DSN) hook exactly once.
func TestAdminFailSendsDSN(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "b", Size: 10,
		Notify: "FAILURE", Ret: "FULL", EnvID: "ENV-9", ORcpt: "rfc822;r@y.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	var bounced atomic.Int64
	var gotNotify, gotRet, gotEnvID, gotORcpt string
	n, err := queue.Fail(ctx, p, queue.Filter{IDs: []int64{id}}, func(ctx context.Context, m queue.Msg) error {
		bounced.Add(1)
		gotNotify, gotRet, gotEnvID, gotORcpt = m.Notify, m.Ret, m.EnvID, m.ORcpt
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("Fail: n=%d err=%v", n, err)
	}
	if bounced.Load() != 1 {
		t.Fatalf("DSN hook fired %d times, want 1", bounced.Load())
	}
	// The failed Msg passed to the DSN hook must carry the RFC 3461 params so the
	// admin-triggered bounce honors NOTIFY/RET/ENVID/ORCPT (regression: Fail's
	// SELECT once omitted these columns).
	if gotNotify != "FAILURE" || gotRet != "FULL" || gotEnvID != "ENV-9" || gotORcpt != "rfc822;r@y.example" {
		t.Fatalf("Fail dropped DSN params: notify=%q ret=%q envid=%q orcpt=%q", gotNotify, gotRet, gotEnvID, gotORcpt)
	}
	var live int
	var kind string
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, id).Scan(&live)
	if live != 0 {
		t.Fatalf("failed message still live")
	}
	if err := p.QueryRow(ctx, `SELECT kind FROM queue_log WHERE queue_id=$1 AND keep_until IS NOT NULL`, id).Scan(&kind); err != nil {
		t.Fatalf("no terminal log entry: %v", err)
	}
	if kind != "failed" {
		t.Fatalf("terminal entry %q; want failed", kind)
	}
}

// TestHoldRuleAutoHold proves a hold rule (a) holds existing matching messages on
// add and (b) auto-holds newly-enqueued matching messages, while non-matching
// messages stay deliverable.
func TestHoldRuleAutoHold(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// Pre-existing message to a domain we'll then hold.
	preID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "victim@blocked.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add a rule holding all mail to blocked.example → existing message held.
	ruleID, held, err := queue.HoldRuleAdd(ctx, p, queue.HoldRule{TenantID: tenantID, RecipientDomain: "blocked.example"})
	if err != nil {
		t.Fatal(err)
	}
	if held != 1 {
		t.Fatalf("HoldRuleAdd held %d existing, want 1", held)
	}
	var preHold bool
	_ = p.QueryRow(ctx, `SELECT hold FROM queue WHERE id=$1`, preID).Scan(&preHold)
	if !preHold {
		t.Fatalf("existing matching message not held")
	}

	// New matching message → auto-held on enqueue.
	newID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "another@blocked.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var newHold bool
	_ = p.QueryRow(ctx, `SELECT hold FROM queue WHERE id=$1`, newID).Scan(&newHold)
	if !newHold {
		t.Fatalf("new matching message not auto-held")
	}

	// Non-matching recipient → NOT held.
	okID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "ok@allowed.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var okHold bool
	_ = p.QueryRow(ctx, `SELECT hold FROM queue WHERE id=$1`, okID).Scan(&okHold)
	if okHold {
		t.Fatalf("non-matching message wrongly held")
	}

	// Removing the rule leaves existing hold states unchanged (mox semantics).
	if err := queue.HoldRuleRemove(ctx, p, ruleID); err != nil {
		t.Fatal(err)
	}
	_ = p.QueryRow(ctx, `SELECT hold FROM queue WHERE id=$1`, newID).Scan(&newHold)
	if !newHold {
		t.Fatalf("removing rule wrongly cleared existing hold")
	}
	rules, err := queue.HoldRuleList(ctx, p, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("rule not removed: %d remain", len(rules))
	}
}

// TestDelayedDSN proves the "still trying" warning DSN fires exactly once when
// attempts first reach DelayThreshold, and not again on later retries.
func TestDelayedDSN(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var delayed atomic.Int64
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		DelayThreshold: 3,
		Deliver:        func(ctx context.Context, m queue.Msg) error { return errors.New("temp") },
		OnDelayed:      func(ctx context.Context, m queue.Msg) error { delayed.Add(1); return nil },
	}
	// Drive 5 failed attempts; the delayed DSN should fire once at attempt 3.
	for i := 0; i < 5; i++ {
		if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := delayed.Load(); got != 1 {
		t.Fatalf("delayed DSN fired %d times, want exactly 1", got)
	}
	var flag bool
	_ = p.QueryRow(ctx, `SELECT delayed_dsn FROM queue WHERE id=$1`, id).Scan(&flag)
	if !flag {
		t.Fatalf("delayed_dsn flag not set")
	}
}
