package postgres

import (
	"context"
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
