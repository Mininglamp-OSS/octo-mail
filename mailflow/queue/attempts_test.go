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

	// Claim-without-real-attempt must NOT burn budget. Simulate a slow worker
	// whose lease is stolen by another node after claim: renewLease (run before
	// each delivery) sees the row is no longer ours and skips delivery, so no
	// attempt is counted.
	if _, err := p.Exec(ctx, `UPDATE queue SET next_attempt=now(), leased_by=NULL, lease_until=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	before := attempts()
	stealer := &queue.Worker{
		Pool: p, NodeID: "n2", Lease: 30 * time.Second, Batch: 1, Backoff: time.Second,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			t.Fatal("delivery must be skipped after lease loss")
			return nil
		},
	}
	// Steal the lease before the worker runs, so renewLease fails and delivery
	// (the Deliver above, which would fail the test) never runs.
	if _, err := p.Exec(ctx, `UPDATE queue SET leased_by='other', lease_until=now()+interval '30 seconds' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := stealer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts() != before {
		t.Fatalf("claim with lost lease burned budget: attempts=%d, want %d", attempts(), before)
	}
	t.Logf("OK: attempts counted per real delivery (1,2); lost-lease claim burns nothing")
}
