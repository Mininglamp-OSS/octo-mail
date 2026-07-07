package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestAttemptsCountedOnRealAttempt proves the H8 fix (#10): the retry budget is
// consumed only by a real delivery attempt, not at claim time. A failed delivery
// increments attempts by exactly one; a claim whose lease is lost before delivery
// (simulated by stealing the lease) burns nothing.
func TestAttemptsCountedOnRealAttempt(t *testing.T) {
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
	attempts := func() int {
		var n int
		if err := p.QueryRow(ctx, `SELECT attempts FROM queue WHERE id=$1`, id).Scan(&n); err != nil {
			t.Fatalf("read attempts: %v", err)
		}
		return n
	}
	if attempts() != 0 {
		t.Fatalf("fresh message attempts=%d, want 0", attempts())
	}

	// One real failed delivery → attempts becomes exactly 1.
	w := &queue.Worker{
		Pool: p, NodeID: "n1", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error { return errors.New("boom") },
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts() != 1 {
		t.Fatalf("after one failed delivery attempts=%d, want 1", attempts())
	}

	// A second real attempt → 2 (force it due first).
	if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts() != 2 {
		t.Fatalf("after two failed deliveries attempts=%d, want 2", attempts())
	}

	// Durability (PR #27 review, Jerry-Xin H8): the attempt must be persisted
	// BEFORE the delivery side effect, fenced by the lease — so a crash after a
	// real attempt but before reschedule/retire commits cannot lose the count and
	// let the message exceed MaxAttempts. Simulate a crash mid-delivery: Deliver
	// panics after we've entered it, and we assert the DB attempts was already
	// bumped (by renewLease, which runs before Deliver).
	if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	before := attempts() // 2 from above
	crasher := &queue.Worker{
		Pool: p, NodeID: "n1", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			panic("simulated crash mid-delivery")
		},
	}
	func() {
		defer func() { _ = recover() }() // swallow the simulated crash
		_, _ = crasher.RunOnce(ctx)
	}()
	// The attempt was durably recorded before Deliver ran, even though the
	// "process" crashed before reschedule/retire could commit.
	if got := attempts(); got != before+1 {
		t.Fatalf("attempt not persisted before delivery side effect: attempts=%d, want %d", got, before+1)
	}

	// Lost-lease claim burns nothing: a row already leased by another node is not
	// re-claimed, so no attempt is recorded.
	if _, err := p.Exec(ctx, `UPDATE queue SET leased_by='other', lease_until=now()+interval '30 seconds', next_attempt=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	held := attempts()
	stealer := &queue.Worker{
		Pool: p, NodeID: "n2", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			t.Fatal("delivery must not run for a row leased by another node")
			return nil
		},
	}
	if _, err := stealer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts() != held {
		t.Fatalf("foreign-leased row burned budget: attempts=%d, want %d", attempts(), held)
	}
	t.Logf("OK: attempts counted per real delivery, persisted before the side effect (crash-safe), foreign-leased burns nothing")
}
