package queue_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// TestExtensionFlagsRoundTrip proves #25-8: the RFC 6152 BODY=8BITMIME and RFC
// 6531 SMTPUTF8 requests captured at submission survive the queue (INSERT →
// claim/RETURNING scan) and reach the Deliverer, so delivery can re-negotiate
// them with the next hop instead of silently downgrading. Before the fix these
// were hardcoded false on delivery.
func TestExtensionFlagsRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	// Enqueue one message WITH both flags and one WITHOUT, to prove the values are
	// carried per-message (not defaulted on).
	idOn, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "on@y.example", BlobRef: "ref1", Size: 10,
		Body8BitMIME: true, SMTPUTF8: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	idOff, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "off@y.example", BlobRef: "ref2", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Capture each claimed Msg via the Deliverer seam.
	got := map[int64]queue.Msg{}
	w := &queue.Worker{
		Pool: p, NodeID: "node", Batch: 10,
		Deliver: func(_ context.Context, m queue.Msg) error {
			got[m.ID] = m
			return nil
		},
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	on, ok := got[idOn]
	if !ok {
		t.Fatalf("message %d (flags on) was not delivered", idOn)
	}
	if !on.Body8BitMIME || !on.SMTPUTF8 {
		t.Fatalf("flags lost through the queue: got Body8BitMIME=%v SMTPUTF8=%v, want both true", on.Body8BitMIME, on.SMTPUTF8)
	}
	off, ok := got[idOff]
	if !ok {
		t.Fatalf("message %d (flags off) was not delivered", idOff)
	}
	if off.Body8BitMIME || off.SMTPUTF8 {
		t.Fatalf("flags spuriously set: got Body8BitMIME=%v SMTPUTF8=%v, want both false", off.Body8BitMIME, off.SMTPUTF8)
	}
	t.Logf("OK: BODY=8BITMIME/SMTPUTF8 survive enqueue→claim per-message and reach the Deliverer")
}
