// Threading is a second async projection over the change-log: it groups messages
// into conversations by RFC 5322 Message-ID / In-Reply-To / References, the same
// identity IMAP THREAD and JMAP threadId share. Like FTS it tails messages by
// createseq behind a per-account cursor, so it never couples to delivery
// latency, and it is a pure, rebuildable fold: dropping thread_id + resetting
// the cursor re-derives identical threads from the log.
//
// Model: a message's references (Message-ID, In-Reply-To, References) are nodes
// in a union-find. Two messages thread together iff their reference sets are
// connected. The thread_id is the smallest message id in the connected
// component, assigned deterministically in log order so a rebuild reproduces it.
package projection

import (
	"context"
	"errors"
	"io"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	moxmessage "github.com/mjl-/mox/message"
)

// ThreadWorker folds messages into thread_id groups.
type ThreadWorker struct {
	Pool  *pgxpool.Pool
	Blob  blob.Store
	Batch int
}

const threadCursor = "threads"

// RunOnceAccount threads up to Batch new messages for one account, advancing the
// threads cursor. Returns the number of messages processed.
func (w *ThreadWorker) RunOnceAccount(ctx context.Context, tenantID, accountID int64) (int, error) {
	batch := w.Batch
	if batch <= 0 {
		batch = 100
	}
	var cursor int64
	err := w.Pool.QueryRow(ctx,
		`SELECT seq FROM projection_cursor WHERE account_id=$1 AND name=$2`,
		accountID, threadCursor).Scan(&cursor)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		cursor = 0
	}

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

	maxSeq := cursor
	for _, m := range msgs {
		refs, err := w.references(ctx, tenantID, m.blobRef, m.prefix)
		if err != nil {
			return 0, err
		}
		threadID, err := w.assignThread(ctx, accountID, m.id, refs)
		if err != nil {
			return 0, err
		}
		if _, err := w.Pool.Exec(ctx,
			`UPDATE messages SET thread_id=$1 WHERE id=$2`, threadID, m.id); err != nil {
			return 0, err
		}
		if m.seq > maxSeq {
			maxSeq = m.seq
		}
	}

	if _, err := w.Pool.Exec(ctx,
		`INSERT INTO projection_cursor (account_id, name, seq) VALUES ($1,$2,$3)
		 ON CONFLICT (account_id, name) DO UPDATE SET seq=EXCLUDED.seq`,
		accountID, threadCursor, maxSeq); err != nil {
		return 0, err
	}
	return len(msgs), nil
}

// assignThread returns the thread_id for a message given its canonical
// references. It records (message_id -> ref) links in thread_refs and finds any
// already-threaded message sharing a reference; if found, the existing thread_id
// is reused, otherwise a new thread rooted at this message's own id is created.
func (w *ThreadWorker) assignThread(ctx context.Context, accountID, msgID int64, refs []string) (int64, error) {
	// Default: a message threads to itself.
	threadID := msgID

	if len(refs) > 0 {
		// Any prior message that shares one of these references dictates the thread.
		var existing *int64
		err := w.Pool.QueryRow(ctx,
			`SELECT m.thread_id
			 FROM thread_refs r
			 JOIN messages m ON m.id = r.message_id
			 WHERE r.account_id=$1 AND r.ref = ANY($2) AND m.thread_id IS NOT NULL
			 ORDER BY m.thread_id
			 LIMIT 1`, accountID, refs).Scan(&existing)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		if existing != nil {
			threadID = *existing
		}
	}

	// Record this message's references for future messages to match against.
	for _, ref := range refs {
		if _, err := w.Pool.Exec(ctx,
			`INSERT INTO thread_refs (account_id, message_id, ref) VALUES ($1,$2,$3)
			 ON CONFLICT DO NOTHING`, accountID, msgID, ref); err != nil {
			return 0, err
		}
	}
	return threadID, nil
}

// references extracts the canonical Message-ID plus all In-Reply-To/References
// ids from a stored message.
func (w *ThreadWorker) references(ctx context.Context, tenantID int64, blobRef string, prefix []byte) ([]string, error) {
	r, err := w.Blob.Open(ctx, tenantID, blob.Ref(blobRef))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	full := append(append([]byte{}, prefix...), body...)
	msg, err := mail.ReadMessage(strings.NewReader(string(full)))
	if err != nil {
		// Unparseable header: no references, threads to itself.
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		for _, tok := range splitIDs(raw) {
			if c, _, err := moxmessage.MessageIDCanonical(tok); err == nil && c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	add(msg.Header.Get("Message-Id"))
	add(msg.Header.Get("In-Reply-To"))
	add(msg.Header.Get("References"))
	return out, nil
}

// splitIDs splits a header value into individual <id> tokens.
func splitIDs(s string) []string {
	var out []string
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		out = append(out, s[i:i+j+1])
		s = s[i+j+1:]
	}
	return out
}

// DrainAccount runs until threading is caught up.
func (w *ThreadWorker) DrainAccount(ctx context.Context, tenantID, accountID int64) error {
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

// RebuildAccount clears thread_id + thread_refs and resets the cursor, re-folding
// the whole log from seq 0.
func (w *ThreadWorker) RebuildAccount(ctx context.Context, tenantID, accountID int64) error {
	if _, err := w.Pool.Exec(ctx, `UPDATE messages SET thread_id=NULL WHERE account_id=$1`, accountID); err != nil {
		return err
	}
	if _, err := w.Pool.Exec(ctx, `DELETE FROM thread_refs WHERE account_id=$1`, accountID); err != nil {
		return err
	}
	if _, err := w.Pool.Exec(ctx,
		`INSERT INTO projection_cursor (account_id, name, seq) VALUES ($1,$2,0)
		 ON CONFLICT (account_id, name) DO UPDATE SET seq=0`,
		accountID, threadCursor); err != nil {
		return err
	}
	return w.DrainAccount(ctx, tenantID, accountID)
}
