package queue_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestDeliveryBoundedByLease is the regression proof for the CRITICAL-2
// double-send fix. Before the fix, RunOnce delivered with the process-lifetime
// context, so a delivery slower than the (unrenewed) lease would still be
// running when another node reclaimed the row — a duplicate SMTP transmission.
//
// Now each delivery runs under a context bounded to strictly less than the lease
// window. This test hands the worker a Deliverer that blocks until its context
// is cancelled and asserts the delivery is aborted well within the lease, rather
// than running unbounded — closing the window in which a second node could
// reclaim and re-send.
func TestDeliveryBoundedByLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	if _, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "deadbeef", Size: 10,
	}); err != nil {
		t.Fatal(err)
	}

	const lease = 2 * time.Second
	var deliverCtxErr error
	var elapsed time.Duration
	w := &queue.Worker{
		Pool: p, NodeID: "n1", Lease: lease, Batch: 1,
		Deliver: func(dctx context.Context, m queue.Msg) error {
			start := time.Now()
			<-dctx.Done() // a hung/slow MX: block until the delivery ctx is cut
			elapsed = time.Since(start)
			deliverCtxErr = dctx.Err()
			return dctx.Err()
		},
	}

	done := make(chan error, 1)
	go func() { _, err := w.RunOnce(ctx); done <- err }()

	select {
	case <-done:
	case <-time.After(lease + 2*time.Second):
		t.Fatal("RunOnce did not return within lease+margin — delivery was not bounded (double-send window open)")
	}

	// The delivery ctx must have been cancelled strictly before the lease elapsed,
	// leaving margin before another node could reclaim the row.
	if deliverCtxErr == nil {
		t.Fatal("delivery context was never cancelled — delivery ran unbounded")
	}
	if elapsed >= lease {
		t.Fatalf("delivery ran %v, not bounded below the %v lease — reclaim window open", elapsed, lease)
	}
	t.Logf("OK: delivery aborted after %v (< %v lease); no unbounded transmission past the lease (CRITICAL-2 closed)", elapsed, lease)
}
