package postgres

import (
	"context"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// ReplayChanges reads change-log entries for an account with seq > since and
// decodes them into []store.Change. This is the primitive behind cross-node
// notification (a remote node replays what it missed) and projection rebuild.
// It is also, by construction, exactly what IMAP CONDSTORE / JMAP Email/changes
// serve — one log, many renderers.
func (s *Store) ReplayChanges(ctx context.Context, accountID int64, since store.ModSeq) ([]store.Change, store.ModSeq, error) {
	seqs, changes, head, err := s.replayWithSeqs(ctx, accountID, since)
	_ = seqs
	return changes, head, err
}

// replayWithSeqs is ReplayChanges plus the per-entry log seq, so a single replay
// from a minimum cursor can be sliced per subscriber (each subscriber keeps only
// entries past ITS own cursor). Returned in ascending seq order. seqs[i] is the
// log position of changes[i]; derived (non-modseq) changes have a real log seq
// here even though their ChangeModSeq() is -1.
func (s *Store) replayWithSeqs(ctx context.Context, accountID int64, since store.ModSeq) ([]store.ModSeq, []store.Change, store.ModSeq, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT seq, kind, payload FROM changelog WHERE account_id=$1 AND seq>$2 ORDER BY seq`,
		accountID, int64(since))
	if err != nil {
		return nil, nil, since, err
	}
	defer rows.Close()

	var seqs []store.ModSeq
	var out []store.Change
	head := since
	for rows.Next() {
		var seq int64
		var kind int16
		var payload []byte
		if err := rows.Scan(&seq, &kind, &payload); err != nil {
			return nil, nil, since, err
		}
		c, err := decodeChange(uint8(kind), payload)
		if err != nil {
			return nil, nil, since, err
		}
		seqs = append(seqs, store.ModSeq(seq))
		out = append(out, c)
		if store.ModSeq(seq) > head {
			head = store.ModSeq(seq)
		}
	}
	return seqs, out, head, rows.Err()
}
