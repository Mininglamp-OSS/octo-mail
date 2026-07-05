package queue_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// resErr is a queue.ResultError carrying an SMTP code/secode for the results test.
type resErr struct {
	code   int
	secode string
}

func (e *resErr) Error() string             { return "smtp " + e.secode }
func (e *resErr) SMTPResult() (int, string) { return e.code, e.secode }

// permErr is a queue.PermanentError (also ResultError) for the fast-fail test.
type permErr struct {
	code int
	perm bool
}

func (e *permErr) Error() string             { return "smtp permanent" }
func (e *permErr) SMTPResult() (int, string) { return e.code, "5.1.1" }
func (e *permErr) Permanent() bool           { return e.perm }

// TestPermanentFailureFastPath proves a permanent (5xx) delivery error fails the
// message on the FIRST attempt — retired-as-failed, OnFailed fired, no further
// retries — while a transient error keeps retrying up to max attempts.
func TestPermanentFailureFastPath(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// Permanent failure on attempt 1.
	permID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "nobody@y.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var bounced, calls int
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			calls++
			return &permErr{code: 550, perm: true}
		},
		OnFailed: func(ctx context.Context, m queue.Msg) error { bounced++; return nil },
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || bounced != 1 {
		t.Fatalf("permanent failure: calls=%d bounced=%d, want 1/1", calls, bounced)
	}
	// Gone from the live queue, retired as failure on attempt 1.
	var live, attempts int
	var kind string
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, permID).Scan(&live)
	if live != 0 {
		t.Fatalf("permanently-failed message still live (would keep retrying)")
	}
	if err := p.QueryRow(ctx,
		`SELECT kind, COALESCE((payload->>'attempts')::int,0) FROM queue_log WHERE queue_id=$1 AND keep_until IS NOT NULL`, permID).
		Scan(&kind, &attempts); err != nil {
		t.Fatalf("no terminal log entry: %v", err)
	}
	if kind != "failed" || attempts != 1 {
		t.Fatalf("terminal: kind=%q attempts=%d, want failed/1", kind, attempts)
	}

	// A transient (non-permanent) error must NOT fast-fail: it reschedules.
	transID, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "busy@y.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	wt := &queue.Worker{
		Pool: p, NodeID: "n2", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error { return &permErr{code: 451, perm: false} },
		OnFailed: func(ctx context.Context, m queue.Msg) error {
			t.Fatalf("transient error must not fire OnFailed on attempt 1")
			return nil
		},
	}
	if _, err := wt.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var stillLive int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, transID).Scan(&stillLive)
	if stillLive != 1 {
		t.Fatalf("transient failure should remain queued for retry, live=%d", stillLive)
	}
}

// TestResultsHistory proves each delivery attempt records a queue_results row
// with the SMTP code/secode/error extracted from the Deliverer's ResultError, and
// that the history is queryable and survives retirement (same id).
func TestResultsHistory(t *testing.T) {
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

	// Two transient failures (recorded with code) then a success.
	var calls int
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			calls++
			if calls <= 2 {
				return &resErr{code: 451, secode: "4.3.0"}
			}
			return nil
		},
	}
	for i := 0; i < 3; i++ {
		if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}

	results, err := queue.Results(ctx, p, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	// First two are failures with the SMTP code recorded; last is success.
	for i, r := range results {
		if i < 2 {
			if r.Success || r.Code != 451 || r.Secode != "4.3.0" {
				t.Fatalf("result %d: success=%v code=%d secode=%q, want fail 451 4.3.0", i, r.Success, r.Code, r.Secode)
			}
		} else if !r.Success {
			t.Fatalf("result %d: want success", i)
		}
	}
	// History survives into retirement (message delivered → terminal log entry).
	var retired int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue_log WHERE queue_id=$1 AND kind='delivered'`, id).Scan(&retired)
	if retired != 1 {
		t.Fatalf("message not retired after success")
	}
	if again, _ := queue.Results(ctx, p, id); len(again) != 3 {
		t.Fatalf("results lost after retirement: %d", len(again))
	}
}

// TestRetiredCleanup proves CleanupRetired removes retired rows past keep_until
// (and their results), while keeping still-live ones.
func TestRetiredCleanup(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// Deliver one message so it retires (with default keep window) + a result row.
	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "b", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1,
		Deliver: func(ctx context.Context, m queue.Msg) error { return nil },
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Not yet expired: cleanup removes nothing.
	if n, err := queue.CleanupRetired(ctx, p); err != nil || n != 0 {
		t.Fatalf("premature cleanup: n=%d err=%v", n, err)
	}

	// Force the keep window into the past, then cleanup removes the whole log.
	if _, err := p.Exec(ctx, `UPDATE queue_log SET keep_until = now() - interval '1 minute' WHERE queue_id=$1 AND keep_until IS NOT NULL`, id); err != nil {
		t.Fatal(err)
	}
	n, err := queue.CleanupRetired(ctx, p)
	if err != nil || n != 1 {
		t.Fatalf("cleanup: n=%d err=%v, want 1", n, err)
	}
	var logRows int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue_log WHERE queue_id=$1`, id).Scan(&logRows)
	if logRows != 0 {
		t.Fatalf("after cleanup: %d log rows remain, want 0 (whole log swept)", logRows)
	}
}

// TestRetiredListByKind proves RetiredList returns one entry per terminal log
// entry with the correct kind (delivered/failed/dropped), selecting by kind
// rather than the keep_until retention detail.
func TestRetiredListByKind(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	mk := func(rcpt string) int64 {
		id, err := queue.Enqueue(ctx, p, queue.Msg{
			TenantID: tenantID, AccountID: accID,
			MailFrom: "s@x.example", RcptTo: rcpt, BlobRef: "b", Size: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// delivered
	okID := mk("ok@y.example")
	w := &queue.Worker{Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 1,
		Deliver: func(ctx context.Context, m queue.Msg) error { return nil }}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// failed (admin)
	failID := mk("fail@y.example")
	if _, err := queue.Fail(ctx, p, queue.Filter{IDs: []int64{failID}}, nil); err != nil {
		t.Fatal(err)
	}
	// dropped (admin)
	dropID := mk("drop@y.example")
	if _, err := queue.Drop(ctx, p, queue.Filter{IDs: []int64{dropID}}); err != nil {
		t.Fatal(err)
	}

	entries, err := queue.RetiredList(ctx, p, queue.Filter{TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]string{}
	for _, e := range entries {
		got[e.ID] = e.Kind
	}
	if len(entries) != 3 {
		t.Fatalf("RetiredList returned %d entries, want 3 (one per terminal): %+v", len(entries), got)
	}
	if got[okID] != "delivered" || got[failID] != "failed" || got[dropID] != "dropped" {
		t.Fatalf("wrong kinds: delivered=%q failed=%q dropped=%q", got[okID], got[failID], got[dropID])
	}
	// Success flag derives from kind.
	for _, e := range entries {
		if want := e.Kind == "delivered"; e.Success != want {
			t.Fatalf("entry %d kind=%q Success=%v, want %v", e.ID, e.Kind, e.Success, want)
		}
	}
}

// TestScheduleAtAndRequireTLSSet proves ScheduleAt sets an absolute next_attempt
// and RequireTLSSet persists the tri-state override (readable via List and the
// worker's claim).
func TestScheduleAtAndRequireTLSSet(t *testing.T) {
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

	// ScheduleAt: push next_attempt 2h out.
	at := time.Now().Add(2 * time.Hour)
	if n, err := queue.ScheduleAt(ctx, p, queue.Filter{IDs: []int64{id}}, at); err != nil || n != 1 {
		t.Fatalf("ScheduleAt: n=%d err=%v", n, err)
	}
	var delaySecs float64
	_ = p.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM (next_attempt - now())) FROM queue WHERE id=$1`, id).Scan(&delaySecs)
	if delaySecs < 3600 {
		t.Fatalf("ScheduleAt did not defer next_attempt (delta=%.0fs, want ~7200)", delaySecs)
	}

	// RequireTLSSet: policy(nil) → yes(true) → no(false), each visible in List.
	yes := true
	if n, err := queue.RequireTLSSet(ctx, p, queue.Filter{IDs: []int64{id}}, &yes); err != nil || n != 1 {
		t.Fatalf("RequireTLSSet yes: n=%d err=%v", n, err)
	}
	entries, err := queue.List(ctx, p, queue.Filter{IDs: []int64{id}})
	if err != nil || len(entries) != 1 {
		t.Fatalf("List: %d entries err=%v", len(entries), err)
	}
	if entries[0].RequireTLS == nil || !*entries[0].RequireTLS {
		t.Fatalf("RequireTLS not set to true: %+v", entries[0].RequireTLS)
	}

	// Reset to nil (policy).
	if _, err := queue.RequireTLSSet(ctx, p, queue.Filter{IDs: []int64{id}}, nil); err != nil {
		t.Fatal(err)
	}
	entries, _ = queue.List(ctx, p, queue.Filter{IDs: []int64{id}})
	if entries[0].RequireTLS != nil {
		t.Fatalf("RequireTLS not reset to nil: %+v", entries[0].RequireTLS)
	}
}
