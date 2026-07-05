package queue_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestBounceToSuppression proves R2-4: when a message fails permanently (max
// attempts reached), the worker's OnFailed hook adds the recipient to the
// suppression list (as cmd/octo-mail wires it), so subsequent sends are blocked.
func TestBounceToSuppression(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// Enqueue a message with max_attempts=1 so one failure retires it permanently.
	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "me@sender.example", RcptTo: "dead@remote.example",
		BlobRef: "ref", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE queue SET max_attempts=1 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}

	sup := &deliverability.Suppressions{Pool: p}
	var onFailedCalled bool
	w := &queue.Worker{
		Pool: p, NodeID: "n1", Batch: 5,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			return fmt.Errorf("550 5.1.1 no such user") // permanent-looking failure
		},
		OnFailed: func(ctx context.Context, m queue.Msg) error {
			onFailedCalled = true
			return sup.Add(ctx, m.TenantID, m.AccountID, m.RcptTo, "hard bounce (max attempts)")
		},
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !onFailedCalled {
		t.Fatalf("OnFailed not invoked on permanent failure")
	}
	// The recipient must now be suppressed.
	deadline := time.Now().Add(2 * time.Second)
	var suppressed bool
	for time.Now().Before(deadline) {
		suppressed, _ = sup.Suppressed(ctx, accID, "dead@remote.example")
		if suppressed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !suppressed {
		t.Fatalf("recipient not suppressed after permanent bounce")
	}
	// And a fresh send to that recipient is blocked by the suppression check.
	blocked, _ := sup.Suppressed(ctx, accID, "dead@remote.example")
	if !blocked {
		t.Fatalf("suppression not effective for subsequent sends")
	}
	t.Logf("OK: permanent bounce → OnFailed → recipient suppressed → subsequent sends blocked")
}
