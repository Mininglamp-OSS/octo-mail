// Package projections holds async, rebuildable folds of the change-log that do
// not need read-your-write consistency — full-text search first. A projection
// worker folds the messages table by createseq (which equals the changelog seq
// at insertion) behind a per-account high-water cursor, so delivery latency is
// never coupled to indexing. Adding a projection means inserting a cursor at
// 0 and letting the worker fold the whole history up to the live head, then stay
// live — no lock, no downtime. Dropping and rebuilding is the same code path
// from seq 0.
package projection

import (
	"context"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// FTSWorker folds message bodies into the fts tsvector projection.
type FTSWorker struct {
	Pool *pgxpool.Pool
	Blob blob.Store
	// Batch bounds how many messages are indexed per RunOnce call per account.
	Batch int
}

const ftsCursor = "fts"

// RunOnceAccount indexes up to Batch new messages for one account (those with
// createseq beyond the fts cursor), advancing the cursor. Returns the number of
// messages indexed. Safe to call repeatedly; when it returns 0 the projection
// is caught up to the log head.
func (w *FTSWorker) RunOnceAccount(ctx context.Context, tenantID, accountID int64) (int, error) {
	batch := w.Batch
	if batch <= 0 {
		batch = 100
	}

	// Read the cursor (0 if absent).
	var cursor int64
	err := w.Pool.QueryRow(ctx,
		`SELECT seq FROM projection_cursor WHERE account_id=$1 AND name=$2`,
		accountID, ftsCursor).Scan(&cursor)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		cursor = 0
	}

	// Fetch the next batch of messages past the cursor, in log order. We index
	// both live and expunged rows (an expunged message may still be searched in
	// some clients; the fts row is harmless and GC'd on rebuild) — but to keep it
	// simple and correct we index by createseq monotonically.
	rows, err := w.Pool.Query(ctx,
		`SELECT id, createseq, blob_ref, msg_prefix
		 FROM messages
		 WHERE account_id=$1 AND createseq>$2
		 ORDER BY createseq
		 LIMIT $3`, accountID, cursor, batch)
	if err != nil {
		return 0, err
	}
	type msg struct {
		id      int64
		seq     int64
		blobRef string
		prefix  []byte
	}
	var msgs []msg
	for rows.Next() {
		var m msg
		if err := rows.Scan(&m.id, &m.seq, &m.blobRef, &m.prefix); err != nil {
			rows.Close()
			return 0, err
		}
		msgs = append(msgs, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, nil
	}

	// Phase 1 — read each message's text OUTSIDE any transaction (blob reads are
	// network I/O; holding a tx open across the whole batch would be a long-lived
	// transaction).
	texts := make([]string, len(msgs))
	for i, m := range msgs {
		text, err := w.readText(ctx, tenantID, m.blobRef, m.prefix)
		if err != nil {
			return 0, err
		}
		texts[i] = text
	}

	// Phase 2 — upsert every tsvector and advance the cursor in ONE transaction, so
	// the cursor moves iff all upserts in the batch are durable. A crash mid-batch
	// rolls back and the batch re-runs from the unchanged cursor.
	maxSeq := cursor
	err = pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		for i, m := range msgs {
			// Upsert the tsvector. to_tsvector runs in Postgres so we never ship a
			// parsed vector over the wire.
			if _, err := tx.Exec(ctx,
				`INSERT INTO fts (account_id, message_id, tsv)
				 VALUES ($1,$2, to_tsvector('simple', $3))
				 ON CONFLICT (account_id, message_id)
				 DO UPDATE SET tsv = EXCLUDED.tsv`,
				accountID, m.id, texts[i]); err != nil {
				return err
			}
			if m.seq > maxSeq {
				maxSeq = m.seq
			}
		}
		// Advance the cursor to the highest indexed seq.
		if _, err := tx.Exec(ctx,
			`INSERT INTO projection_cursor (account_id, name, seq)
			 VALUES ($1,$2,$3)
			 ON CONFLICT (account_id, name)
			 DO UPDATE SET seq=EXCLUDED.seq`,
			accountID, ftsCursor, maxSeq); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(msgs), nil
}

// DrainAccount runs RunOnceAccount until the projection is caught up.
func (w *FTSWorker) DrainAccount(ctx context.Context, tenantID, accountID int64) error {
	for {
		n, err := w.RunOnceAccount(ctx, tenantID, accountID)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

// RebuildAccount drops the fts projection for an account and resets its cursor,
// so the next Drain/RunOnce re-folds the whole log from seq 0. This is the
// "rebuild a projection" primitive — the same fold, from the beginning.
func (w *FTSWorker) RebuildAccount(ctx context.Context, tenantID, accountID int64) error {
	if _, err := w.Pool.Exec(ctx, `DELETE FROM fts WHERE account_id=$1`, accountID); err != nil {
		return err
	}
	if _, err := w.Pool.Exec(ctx,
		`INSERT INTO projection_cursor (account_id, name, seq) VALUES ($1,$2,0)
		 ON CONFLICT (account_id, name) DO UPDATE SET seq=0`,
		accountID, ftsCursor); err != nil {
		return err
	}
	return w.DrainAccount(ctx, tenantID, accountID)
}

// readText returns the indexable text of a message: the generated prefix
// (headers) followed by the stored body. Postgres tokenizes it via to_tsvector.
func (w *FTSWorker) readText(ctx context.Context, tenantID int64, blobRef string, prefix []byte) (string, error) {
	r, err := w.Blob.Open(ctx, tenantID, blob.Ref(blobRef))
	if err != nil {
		return "", err
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(prefix) + string(body), nil
}
