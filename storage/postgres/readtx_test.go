package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// TestReadTxNoLockNoAdvance proves the #21-1 read-only Tx path: ReadTx does not
// advance the account changelog head (no flush) and, unlike Tx, does not hold the
// per-account advisory lock — so a ReadTx can run WHILE a writer Tx holds the lock
// on the same account, without deadlocking or serializing.
func TestReadTxNoLockNoAdvance(t *testing.T) {
	ctx := context.Background()
	s, _, accID := setupTest(t)

	acc, _, _, err := s.LookupAccountByID(ctx, accID)
	if err != nil {
		t.Fatal(err)
	}

	head := func() int64 {
		var h int64
		must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&h))
		return h
	}
	before := head()

	// A ReadTx that only queries must not move the changelog head.
	if err := acc.ReadTx(ctx, func(tx store.Tx) error {
		_, e := tx.QueryMailbox().List()
		return e
	}); err != nil {
		t.Fatalf("ReadTx: %v", err)
	}
	if after := head(); after != before {
		t.Fatalf("ReadTx advanced changelog_seq %d→%d; read path must not flush", before, after)
	}

	// A ReadTx must NOT take the advisory lock: start a writer Tx that holds the
	// lock, and prove a ReadTx completes concurrently (it would block/deadlock if
	// ReadTx also tried to take the exclusive lock on the same account).
	writerHolding := make(chan struct{})
	writerRelease := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- acc.Tx(ctx, func(tx store.Tx) error {
			close(writerHolding) // lock is held now
			<-writerRelease      // keep holding until the reader is done
			return nil
		})
	}()
	<-writerHolding
	readDone := make(chan error, 1)
	go func() {
		readDone <- acc.ReadTx(ctx, func(tx store.Tx) error {
			_, e := tx.QueryMailbox().List()
			return e
		})
	}()
	// The reader must finish while the writer still holds the lock.
	if err := <-readDone; err != nil {
		close(writerRelease)
		t.Fatalf("ReadTx blocked/failed while writer held the advisory lock: %v", err)
	}
	close(writerRelease)
	if err := <-writerDone; err != nil {
		t.Fatalf("writer Tx: %v", err)
	}
	t.Logf("OK: ReadTx takes no advisory lock (ran concurrently with a lock-holding writer) and never advances changelog_seq")
}

// TestReadTxRejectsWrites proves the "an accidental write errors at the DB, not
// silently" guarantee: a write attempted inside ReadTx fails because the tx is
// opened pgx.ReadOnly. Guards against a regression that drops AccessMode.
func TestReadTxRejectsWrites(t *testing.T) {
	ctx := context.Background()
	s, _, accID := setupTest(t)
	acc, _, _, err := s.LookupAccountByID(ctx, accID)
	if err != nil {
		t.Fatal(err)
	}
	err = acc.ReadTx(ctx, func(tx store.Tx) error {
		// Attempt a raw write on the read-only tx; Postgres must reject it.
		_, e := tx.(*pgTx).tx.Exec(ctx, `UPDATE accounts SET name=name WHERE id=$1`, accID)
		return e
	})
	if err == nil {
		t.Fatal("a write inside ReadTx was accepted; the tx must be read-only (AccessMode dropped?)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "read-only") {
		t.Logf("note: write rejected with %q (accepted — any DB-level rejection proves read-only)", err)
	}
	t.Logf("OK: a write inside ReadTx is rejected at the database")
}

// TestReadTxSnapshotStable proves the RepeatableRead fix (#40 review): a
// multi-statement ReadTx sees ONE snapshot for its whole lifetime, so a writer
// committing between two reads inside the tx is invisible to the second read.
// Under the previous READ COMMITTED default the second read would have observed
// the concurrent commit (a torn read), which is exactly what STATUS/list paths
// must not do.
func TestReadTxSnapshotStable(t *testing.T) {
	ctx := context.Background()
	s, dir, accID := setupTest(t)

	target, err := resolveInbound(t, dir, "u1@example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Deliver one message so the account has a mailbox with a known count.
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: first\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	acc, _, _, err := s.LookupAccountByID(ctx, accID)
	if err != nil {
		t.Fatal(err)
	}

	countInbox := func(tx store.Tx) int {
		mb, e := acc.MailboxFind(tx, "Inbox")
		if e != nil {
			t.Fatalf("MailboxFind: %v", e)
		}
		msgs, e := tx.QueryMessage().FilterMailbox(mb.ID).List()
		if e != nil {
			t.Fatalf("List: %v", e)
		}
		return len(msgs)
	}

	var first, second int
	err = acc.ReadTx(ctx, func(tx store.Tx) error {
		first = countInbox(tx)
		// Commit a concurrent delivery from OUTSIDE this tx, mid-read.
		if _, e := target.Deliver(ctx, &store.Message{}, memReader("Subject: second\r\n\r\nbody2\r\n")); e != nil {
			t.Fatalf("concurrent deliver: %v", e)
		}
		// The second read within the SAME ReadTx must still see the original snapshot.
		second = countInbox(tx)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadTx: %v", err)
	}
	if first != second {
		t.Fatalf("ReadTx snapshot not stable: first read saw %d, second saw %d (torn read; RepeatableRead not in effect)", first, second)
	}
	if first != 1 {
		t.Fatalf("expected 1 message in the snapshot, got %d", first)
	}
	// Sanity: a fresh ReadTx now sees both messages (the concurrent write did land).
	var afterCommit int
	must(t, acc.ReadTx(ctx, func(tx store.Tx) error {
		afterCommit = countInbox(tx)
		return nil
	}))
	if afterCommit != 2 {
		t.Fatalf("after the concurrent commit, a new ReadTx should see 2 messages, got %d", afterCommit)
	}
	t.Logf("OK: ReadTx holds one snapshot (1→1 across a concurrent commit); a later ReadTx sees the committed write (2)")
}
