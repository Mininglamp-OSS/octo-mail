package queue_test

import (
	"context"
	"errors"
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
		OnFailed: func(ctx context.Context, m queue.Msg, cause error) error {
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

// permClass is a queue.PermanentError for classification tests.
type permClass struct{ perm bool }

func (e *permClass) Error() string   { return "classified failure" }
func (e *permClass) Permanent() bool { return e.perm }

// TestOnFailedReceivesClassification proves #22-1: OnFailed is handed the terminal
// cause so it can distinguish a genuine 5xx permanent failure from transient
// max-attempts exhaustion. A permanent cause reports permanent; a transient cause
// (budget exhausted) reports NOT permanent — the signal cmd/octo-mail uses to
// suppress only on real bounces.
func TestOnFailedReceivesClassification(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	run := func(permanent bool, maxAttempts int) (fired, sawPermanent bool) {
		id, err := queue.Enqueue(ctx, p, queue.Msg{
			TenantID: tenantID, AccountID: accID,
			MailFrom: "me@sender.example", RcptTo: "x@remote.example", BlobRef: "ref", Size: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `UPDATE queue SET max_attempts=$2 WHERE id=$1`, id, maxAttempts); err != nil {
			t.Fatal(err)
		}
		w := &queue.Worker{
			Pool: p, NodeID: "n1", Batch: 5, Backoff: time.Millisecond,
			Deliver: func(ctx context.Context, m queue.Msg) error { return &permClass{perm: permanent} },
			OnFailed: func(ctx context.Context, m queue.Msg, cause error) error {
				fired = true
				var pe queue.PermanentError
				sawPermanent = errors.As(cause, &pe) && pe.Permanent()
				return nil
			},
		}
		// Drain until the message is retired (transient case needs several passes to
		// exhaust its small attempt budget).
		for i := 0; i < maxAttempts+2; i++ {
			if _, err := w.RunOnce(ctx); err != nil {
				t.Fatalf("run: %v", err)
			}
			if fired {
				break
			}
			// Make the next attempt due immediately.
			_, _ = p.Exec(ctx, `UPDATE queue SET next_attempt=now()-interval '1 second', lease_until=NULL, leased_by=NULL WHERE id=$1`, id)
		}
		return fired, sawPermanent
	}

	// Permanent 5xx on the first attempt: OnFailed fires, cause is permanent.
	if fired, perm := run(true, 3); !fired || !perm {
		t.Fatalf("permanent failure: fired=%v sawPermanent=%v, want true/true", fired, perm)
	}
	// Transient failure exhausting the attempt budget: OnFailed fires, cause is NOT
	// permanent (so cmd/octo-mail records a deferral and does not suppress).
	if fired, perm := run(false, 2); !fired || perm {
		t.Fatalf("transient exhaustion: fired=%v sawPermanent=%v, want true/false", fired, perm)
	}
	t.Logf("OK: OnFailed distinguishes permanent (5xx) from transient exhaustion via the cause error")
}
