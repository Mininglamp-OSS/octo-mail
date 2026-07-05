package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// CollectGarbage reclaims storage that message expunge leaves behind. Expunge is
// a soft delete (messages.expunged=true) because the live read paths never need
// an expunged row — the durable expunge history that IMAP QRESYNC VANISHED is
// built from lives in the changelog (see account.ExpungedUIDsSince), not in the
// message row. So an expunged row is dead weight, and its body blob is
// reclaimable once nothing else points at it.
//
// The sweep, per run:
//  1. Hard-delete expunged message rows, capturing their (tenant_id, blob_ref).
//  2. For each distinct freed (tenant, ref), delete the blob IFF no live message
//     row and no queue row still reference it in that tenant. This respects both
//     content-addressed dedup and JMAP sibling sharing (AddSibling reuses one
//     blob_ref across rows): a blob is removed only when its last referrer is
//     gone.
//
// Blob deletion happens AFTER the row delete commits, so a crash between the two
// can only leave an unreferenced blob (reclaimed on the next run), never a live
// row pointing at a missing blob. Returns rows deleted and blobs removed.
//
// It is safe to run concurrently on multiple nodes: the row delete uses FOR
// UPDATE SKIP LOCKED so nodes take disjoint batches, and the reference re-check
// before each blob delete is authoritative at delete time. limit bounds the
// batch (0 uses a default of 1000).
func (s *Store) CollectGarbage(ctx context.Context, limit int) (rowsDeleted int64, blobsRemoved int64, err error) {
	if limit <= 0 {
		limit = 1000
	}

	type ref struct {
		tenantID int64
		blobRef  string
	}
	var freed []ref

	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// messages carries account_id, not tenant_id; the blob namespace is keyed
		// by tenant, so resolve it via accounts in the RETURNING projection.
		rows, e := tx.Query(ctx,
			`WITH doomed AS (
			     SELECT account_id, id FROM messages
			     WHERE expunged
			     ORDER BY account_id, id
			     FOR UPDATE SKIP LOCKED
			     LIMIT $1
			 ), del AS (
			     DELETE FROM messages m
			     USING doomed d
			     WHERE m.account_id=d.account_id AND m.id=d.id
			     RETURNING m.account_id, m.blob_ref
			 )
			 SELECT a.tenant_id, del.blob_ref FROM del JOIN accounts a ON a.id=del.account_id`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r ref
			if e := rows.Scan(&r.tenantID, &r.blobRef); e != nil {
				return e
			}
			freed = append(freed, r)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, 0, fmt.Errorf("gc: delete expunged rows: %w", err)
	}
	rowsDeleted = int64(len(freed))

	// Dedup the freed refs so a blob shared by several just-deleted rows is
	// checked (and at most deleted) once.
	seen := make(map[ref]bool, len(freed))
	for _, r := range freed {
		if seen[r] {
			continue
		}
		seen[r] = true

		// Authoritative referrer re-check at delete time: any live message row (in
		// this tenant, via accounts) OR any queued outbound message keeps the blob
		// alive. messages has no tenant_id, so join through accounts.
		var referenced bool
		if e := s.Pool.QueryRow(ctx,
			`SELECT EXISTS (
			         SELECT 1 FROM messages m JOIN accounts a ON a.id=m.account_id
			         WHERE a.tenant_id=$1 AND m.blob_ref=$2
			     )
			     OR EXISTS (SELECT 1 FROM queue WHERE tenant_id=$1 AND blob_ref=$2)`,
			r.tenantID, r.blobRef).Scan(&referenced); e != nil {
			return rowsDeleted, blobsRemoved, fmt.Errorf("gc: refcheck %s: %w", r.blobRef, e)
		}
		if referenced {
			continue
		}
		if e := s.Blob.Delete(ctx, r.tenantID, blob.Ref(r.blobRef)); e != nil {
			return rowsDeleted, blobsRemoved, fmt.Errorf("gc: delete blob %s: %w", r.blobRef, e)
		}
		blobsRemoved++
	}
	return rowsDeleted, blobsRemoved, nil
}
