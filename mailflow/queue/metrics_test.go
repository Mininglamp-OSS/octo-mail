package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestQueueDepthCounts proves Depth returns correct due/held/total counts across
// a mix of due, future (not-yet-due), and held messages.
func TestQueueDepthCounts(t *testing.T) {
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
	// Two due-now.
	mk("a@y.example")
	mk("b@y.example")
	// One scheduled in the future (not due).
	future := mk("c@y.example")
	if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now()+interval '1 hour' WHERE id=$1`, future); err != nil {
		t.Fatal(err)
	}
	// One held.
	held := mk("d@y.example")
	if _, err := queue.HoldSet(ctx, p, queue.Filter{IDs: []int64{held}}, true); err != nil {
		t.Fatal(err)
	}

	d, err := queue.Depth(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Total != 4 {
		t.Fatalf("total=%d, want 4", d.Total)
	}
	if d.Due != 2 {
		t.Fatalf("due=%d, want 2 (future and held excluded)", d.Due)
	}
	if d.Held != 1 {
		t.Fatalf("held=%d, want 1", d.Held)
	}
}

// TestObserveDeliveryHook proves the worker fires ObserveDelivery with the attempt
// duration and the correct result label for both success and failure.
func TestObserveDeliveryHook(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	okID, _ := queue.Enqueue(ctx, p, queue.Msg{TenantID: tenantID, AccountID: accID, MailFrom: "s@x.example", RcptTo: "ok@y.example", BlobRef: "b", Size: 10})
	_, _ = queue.Enqueue(ctx, p, queue.Msg{TenantID: tenantID, AccountID: accID, MailFrom: "s@x.example", RcptTo: "bad@y.example", BlobRef: "b", Size: 10})

	var results []string
	var observed int
	w := &queue.Worker{
		Pool: p, NodeID: "n", Lease: 30 * time.Second, Batch: 10, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			if m.ID == okID {
				return nil
			}
			return errors.New("boom")
		},
		ObserveDelivery: func(d time.Duration, result string) {
			observed++
			results = append(results, result)
		},
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if observed != 2 {
		t.Fatalf("ObserveDelivery fired %d times, want 2", observed)
	}
	var ok, errc int
	for _, r := range results {
		switch r {
		case "ok":
			ok++
		case "error":
			errc++
		default:
			t.Fatalf("unexpected result label %q", r)
		}
	}
	if ok != 1 || errc != 1 {
		t.Fatalf("result labels ok=%d error=%d, want 1/1", ok, errc)
	}
}
