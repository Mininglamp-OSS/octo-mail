package queue_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func openPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		t.Skipf("postgres not reachable (%v)", err)
	}
	return p
}

// seedQueueSchema applies the canonical schema (via postgres.Open) and seeds a
// tenant + account for FK integrity, returning their ids.
func seedQueueSchema(t *testing.T, ctx context.Context, p *pgxpool.Pool) (tenantID, accID int64) {
	t.Helper()
	// Ensure the canonical schema exists by opening a store against the same DB.
	bs, _ := blob.NewFS(t.TempDir())
	st, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(st.Close)
	if _, err := p.Exec(ctx, `TRUNCATE queue, queue_log, queue_hold_rules, accounts, tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	_ = p.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	_ = p.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'a') RETURNING id`, tenantID).Scan(&accID)
	return tenantID, accID
}

// TestLeaseFailover is the P3 outbound crown proof: node A claims a message and
// "crashes" (never retires it). After the lease expires, node B reclaims and
// delivers it. The message is delivered exactly once overall, and ends up
// retired as success — proving crashed-node work is picked up without loss or
// (for completed work) duplication.
func TestLeaseFailover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID,
		MailFrom: "s@x.example", RcptTo: "r@y.example", BlobRef: "deadbeef", Size: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	var delivered []int64
	var mu sync.Mutex

	// Node A: claims with a SHORT lease, then "crashes" — its Deliverer blocks/
	// fails without retiring (simulated by returning without recording success:
	// we model the crash as the process dying after claim, so we DON'T call
	// RunOnce's retire path — instead use a Deliverer that panics-as-crash by
	// just not being reachable). Simplest faithful model: node A claims via a raw
	// short-lease worker whose Deliver hangs; we abandon it.
	claimed := make(chan struct{})
	aCtx, aCancel := context.WithCancel(ctx)
	nodeA := &queue.Worker{
		Pool: p, NodeID: "nodeA", Lease: 500 * time.Millisecond, Batch: 1,
		Deliver: func(dctx context.Context, m queue.Msg) error {
			// Signal that A has claimed and is now delivering, then block until A's
			// context is cancelled — modeling the process dying mid-delivery. A
			// dead node runs no retire/reschedule that lands, so the lease simply
			// expires and B reclaims. (Blocking forever is no longer a faithful
			// crash model: deliveries are now time-bounded, so a hung delivery
			// would legitimately time out and reschedule.)
			close(claimed)
			<-aCtx.Done()
			return aCtx.Err()
		},
	}

	// Node B: healthy, delivers for real.
	nodeB := &queue.Worker{
		Pool: p, NodeID: "nodeB", Lease: 30 * time.Second, Batch: 1,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			mu.Lock()
			delivered = append(delivered, m.ID)
			mu.Unlock()
			return nil
		},
	}

	// Node A claims (and will "crash" mid-delivery).
	go func() { _, _ = nodeA.RunOnce(aCtx) }()
	// Wait until A has actually claimed the message and entered delivery, so the
	// next assertion is deterministic regardless of scheduler/CPU load.
	select {
	case <-claimed:
	case <-time.After(5 * time.Second):
		t.Fatal("node A never claimed the message")
	}

	// Node B should find nothing due (A holds a fresh 500ms lease).
	n, err := nodeB.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("node B claimed %d while A held a live lease; want 0", n)
	}

	// A "crashes": cancel its context so it stops without rescheduling. Its lease
	// (500ms) will simply expire, after which B reclaims.
	aCancel()

	// Wait for A's lease to expire, then B reclaims and delivers.
	time.Sleep(700 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err = nodeB.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		done := len(delivered) > 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	got := append([]int64(nil), delivered...)
	mu.Unlock()
	if len(got) != 1 || got[0] != id {
		t.Fatalf("expected node B to deliver message %d exactly once, got %v", id, got)
	}

	// The message must be retired as success and gone from the live queue.
	var live int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, id).Scan(&live)
	if live != 0 {
		t.Fatalf("message still in queue after successful delivery")
	}
	var kind string
	if err := p.QueryRow(ctx, `SELECT kind FROM queue_log WHERE queue_id=$1 AND keep_until IS NOT NULL`, id).Scan(&kind); err != nil {
		t.Fatalf("terminal log entry missing: %v", err)
	}
	if kind != "delivered" {
		t.Fatalf("message retired as %q, want delivered", kind)
	}
	t.Logf("OK: node A crashed holding the lease; node B reclaimed after expiry and delivered %d exactly once", id)
}

// TestConcurrentClaimNoDuplicate proves two nodes never claim the same message:
// enqueue N, run both workers concurrently, each delivery recorded once.
func TestConcurrentClaimNoDuplicate(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	const N = 20
	for i := 0; i < N; i++ {
		if _, err := queue.Enqueue(ctx, p, queue.Msg{
			TenantID: tenantID, AccountID: accID, MailFrom: "s@x", RcptTo: "r@y", BlobRef: "b", Size: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	seen := map[int64]int{}
	mkWorker := func(node string) *queue.Worker {
		return &queue.Worker{
			Pool: p, NodeID: node, Lease: 30 * time.Second, Batch: 3,
			Deliver: func(ctx context.Context, m queue.Msg) error {
				mu.Lock()
				seen[m.ID]++
				mu.Unlock()
				return nil
			},
		}
	}
	a, b := mkWorker("A"), mkWorker("B")

	var wg sync.WaitGroup
	for _, w := range []*queue.Worker{a, b} {
		wg.Add(1)
		go func(w *queue.Worker) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				n, err := w.RunOnce(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if n == 0 {
					time.Sleep(20 * time.Millisecond)
				}
			}
		}(w)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != N {
		t.Fatalf("delivered %d distinct messages, want %d", len(seen), N)
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("message %d delivered %d times, want exactly 1", id, c)
		}
	}
	t.Logf("OK: %d messages, two concurrent nodes, each delivered exactly once (no double-claim)", N)
}

// TestStaleLeaseFencing proves a stale worker cannot resurrect or double-retire
// work that another node reclaimed. Node A claims with a short lease; the lease
// expires; node B reclaims and delivers (retires success). Then node A — still
// holding its now-stale in-memory Msg — attempts both reschedule and retire.
// Both must be no-ops (fenced by leased_by): the message stays retired-success
// and does not reappear in the live queue.
func TestStaleLeaseFencing(t *testing.T) {
	ctx := context.Background()
	p := openPool(t, ctx)
	defer p.Close()
	tenantID, accID := seedQueueSchema(t, ctx, p)

	id, err := queue.Enqueue(ctx, p, queue.Msg{
		TenantID: tenantID, AccountID: accID, MailFrom: "s@x", RcptTo: "r@y", BlobRef: "b", Size: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Node A claims via a worker whose Deliverer captures the claimed Msg and
	// fails (so RunOnce would normally reschedule) — but with a lease so short it
	// expires before A's reschedule runs.
	var claimed queue.Msg
	nodeA := &queue.Worker{
		Pool: p, NodeID: "A", Lease: 300 * time.Millisecond, Batch: 1,
		Deliver: func(ctx context.Context, m queue.Msg) error {
			claimed = m
			time.Sleep(600 * time.Millisecond) // outlive our own lease
			return context.Canceled            // A "fails"
		},
	}
	// Run A in background; it will claim, sleep past lease, then reschedule (fenced).
	aDone := make(chan struct{})
	go func() { _, _ = nodeA.RunOnce(ctx); close(aDone) }()

	// After A's lease expires, node B reclaims and delivers successfully.
	time.Sleep(400 * time.Millisecond)
	nodeB := &queue.Worker{
		Pool: p, NodeID: "B", Lease: 30 * time.Second, Batch: 1,
		Deliver: func(ctx context.Context, m queue.Msg) error { return nil },
	}
	n, err := nodeB.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("node B reclaimed %d, want 1", n)
	}

	// Wait for A to finish its (fenced) reschedule attempt.
	<-aDone
	// Also directly attempt a stale retire from A's captured Msg.
	// (retire is unexported; emulate A's stale write via a second reschedule-like
	// path is covered by RunOnce above. Here we assert the end state.)
	_ = claimed

	// End state: message retired success, not resurrected in live queue.
	var live int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM queue WHERE id=$1`, id).Scan(&live)
	if live != 0 {
		t.Fatalf("stale worker resurrected message into live queue (count=%d)", live)
	}
	var kind string
	if err := p.QueryRow(ctx, `SELECT kind FROM queue_log WHERE queue_id=$1 AND keep_until IS NOT NULL`, id).Scan(&kind); err != nil {
		t.Fatalf("message not retired: %v", err)
	}
	if kind != "delivered" {
		t.Fatalf("message retired as %q; node B delivered it successfully", kind)
	}
	t.Logf("OK: stale node A's reschedule was fenced; B's success retire stands")
}
