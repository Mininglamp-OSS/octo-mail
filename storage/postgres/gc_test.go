package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// TestCollectGarbage proves the blob GC reclaims expunged-message storage while
// respecting content-addressed dedup / sibling sharing: an expunged row's blob
// is deleted only when no live row (or queue row) still references it.
//
// Setup in one tenant:
//   - msg1: unique blob refU, expunged        -> row hard-deleted, blob removed
//   - msg2: shared blob refS, expunged
//   - msg3: shared blob refS, LIVE            -> row kept, blob refS retained
func TestCollectGarbage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bs, err := blob.NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, accID, mbID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'a') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Inbox',1,4,1,1) RETURNING id`,
		accID).Scan(&mbID))

	// Store two real blobs so Delete has something to remove.
	refU, _, err := bs.Put(ctx, tenantID, strings.NewReader("unique-body"))
	must(t, err)
	refS, _, err := bs.Put(ctx, tenantID, strings.NewReader("shared-body"))
	must(t, err)

	ins := func(uid int64, ref blob.Ref, expunged bool) {
		_, e := s.Pool.Exec(ctx,
			`INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, expunged, blob_ref, size, received_at, save_date)
			 VALUES ($1,$2,$3,$3,$3,$4,$5,10, now(), now())`,
			accID, mbID, uid, expunged, string(ref))
		must(t, e)
	}
	ins(1, refU, true)  // expunged, unique -> reclaimable
	ins(2, refS, true)  // expunged, shared -> row gone but blob kept
	ins(3, refS, false) // live, shared -> keeps refS alive

	rowsDeleted, blobsRemoved, err := s.CollectGarbage(ctx, 100)
	if err != nil {
		t.Fatalf("CollectGarbage: %v", err)
	}
	if rowsDeleted != 2 {
		t.Fatalf("rowsDeleted=%d, want 2 (both expunged rows)", rowsDeleted)
	}
	if blobsRemoved != 1 {
		t.Fatalf("blobsRemoved=%d, want 1 (only the unique blob; shared blob still live)", blobsRemoved)
	}

	// The unique blob is gone; the shared blob remains (msg3 still references it).
	if _, err := bs.Open(ctx, tenantID, refU); err == nil {
		t.Fatal("unique blob refU still present after GC — not reclaimed")
	}
	r, err := bs.Open(ctx, tenantID, refS)
	if err != nil {
		t.Fatalf("shared blob refS was deleted while a live row references it: %v", err)
	}
	r.Close()

	// Only the live row remains.
	var live int
	must(t, s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1`, accID).Scan(&live))
	if live != 1 {
		t.Fatalf("live message rows=%d, want 1", live)
	}
	t.Logf("OK: GC removed 2 expunged rows + 1 unreferenced blob; shared blob kept for the live row (HIGH-2 closed)")
}
