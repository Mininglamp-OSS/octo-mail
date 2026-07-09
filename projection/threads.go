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
	"bytes"
	"context"
	"errors"
	"io"
	"net/mail"
	"strings"
	"unicode/utf8"

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
		refs, sum, err := w.parseMessage(ctx, tenantID, m.blobRef, m.prefix)
		if err != nil {
			return 0, err
		}
		threadID, err := w.assignThread(ctx, accountID, m.id, refs)
		if err != nil {
			return 0, err
		}
		if _, err := w.Pool.Exec(ctx,
			`UPDATE messages SET thread_id=$1,
			   subject=$3, from_addr=$4, to_addrs=$5, from_search=$6, to_search=$7,
			   preview=$8, summary_folded=true
			 WHERE id=$2`,
			threadID, m.id, sum.subject, sum.from, sum.to, sum.fromSearch, sum.toSearch, sum.preview); err != nil {
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

// msgSummary holds the denormalized list-summary fields extracted during the fold.
type msgSummary struct {
	subject    string
	from       string // sender address (display)
	to         string // space-joined recipient addresses (display)
	fromSearch string // sender name + address (filter)
	toSearch   string // recipient names + addresses (filter)
	preview    string // first ~140 chars of body text
}

// parseMessage reads a stored message once and extracts BOTH its threading
// references (canonical Message-ID + In-Reply-To/References) AND its list-summary
// fields (subject/from/to/preview), so the fold populates thread_id and the
// summary columns from a single blob read + parse.
func (w *ThreadWorker) parseMessage(ctx context.Context, tenantID int64, blobRef string, prefix []byte) ([]string, msgSummary, error) {
	r, err := w.Blob.Open(ctx, tenantID, blob.Ref(blobRef))
	if err != nil {
		return nil, msgSummary{}, err
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, msgSummary{}, err
	}
	full := append(append([]byte{}, prefix...), body...)

	var refs []string
	var sum msgSummary

	// Headers + references via the stdlib parser (matches the prior behavior).
	if msg, err := mail.ReadMessage(strings.NewReader(string(full))); err == nil {
		seen := map[string]bool{}
		add := func(raw string) {
			for _, tok := range splitIDs(raw) {
				if c, _, err := moxmessage.MessageIDCanonical(tok); err == nil && c != "" && !seen[c] {
					seen[c] = true
					refs = append(refs, c)
				}
			}
		}
		add(msg.Header.Get("Message-Id"))
		add(msg.Header.Get("In-Reply-To"))
		add(msg.Header.Get("References"))
	}
	// else: unparseable header → threads to itself, empty summary.

	// Structured envelope + body preview via mox's parser (one parse of full).
	if part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(full), int64(len(full))); err == nil || part.Envelope != nil {
		if env := part.Envelope; env != nil {
			sum.subject = env.Subject
			sum.from = addrDisplay(env.From)
			sum.to = addrDisplay(env.To)
			sum.fromSearch = addrSearch(env.From)
			sum.toSearch = addrSearch(env.To)
		}
		sum.preview = previewOf(&part)
	}
	// Every summary field is written to a Postgres text column, which rejects
	// invalid UTF-8 (SQLSTATE 22021) — that would error the fold UPDATE and wedge
	// the projection forever. Headers can carry invalid UTF-8 (malformed/encoded),
	// and a body part may be a non-UTF-8 charset that the reader doesn't transcode
	// (so even a short preview can be invalid). Scrub ALL of them unconditionally.
	sum.subject = toValidUTF8(sum.subject)
	sum.from = toValidUTF8(sum.from)
	sum.to = toValidUTF8(sum.to)
	sum.fromSearch = toValidUTF8(sum.fromSearch)
	sum.toSearch = toValidUTF8(sum.toSearch)
	sum.preview = toValidUTF8(sum.preview)
	return refs, sum, nil
}

// addrDisplay renders an address list to bare "user@host" values, space-joined —
// the DISPLAY form stored in from_addr/to_addrs (clients get real addresses and a
// correct recipient count; no display-name tokens shattering the split).
func addrDisplay(as []moxmessage.Address) string {
	var parts []string
	for _, a := range as {
		parts = append(parts, a.User+"@"+a.Host)
	}
	return strings.Join(parts, " ")
}

// addrSearch renders an address list to "Name user@host" per address, space-joined
// — the FILTER form stored in from_search/to_search, so a substring search matches
// either a display name or an address. Kept separate from the display form so the
// name tokens never corrupt the displayed from/to (see summarize).
func addrSearch(as []moxmessage.Address) string {
	var parts []string
	for _, a := range as {
		s := a.User + "@" + a.Host
		if a.Name != "" {
			s = a.Name + " " + s
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// toValidUTF8 makes a header/body-derived string safe for a Postgres text column:
// it strips NUL (0x00) — which IS valid UTF-8 but Postgres text rejects with
// SQLSTATE 22021 — and replaces any invalid UTF-8 sequences. Either, unhandled,
// would error the fold UPDATE and wedge the projection forever.
func toValidUTF8(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// previewOf returns the first ~140 chars of a message's text body (falling back
// to stripped HTML), whitespace-collapsed — the list-view preview snippet.
func previewOf(part *moxmessage.Part) string {
	var text, html string
	var walk func(p *moxmessage.Part)
	walk = func(p *moxmessage.Part) {
		if len(p.Parts) > 0 {
			for i := range p.Parts {
				walk(&p.Parts[i])
			}
			return
		}
		if !strings.EqualFold(p.MediaType, "TEXT") && p.MediaType != "" {
			return
		}
		rd := p.Reader()
		if rd == nil {
			return
		}
		b, _ := io.ReadAll(rd)
		if strings.EqualFold(p.MediaSubType, "HTML") {
			if html == "" {
				html = string(b)
			}
		} else if text == "" {
			text = string(b)
		}
	}
	walk(part)
	s := text
	if s == "" {
		s = stripHTMLTags(html)
	}
	s = strings.Join(strings.Fields(s), " ")
	// Truncate on a rune boundary (not a byte offset): a mid-rune byte slice would
	// yield invalid UTF-8, which a Postgres text column rejects.
	if len(s) > 140 {
		s = s[:140]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// stripHTMLTags removes tags for a text preview of an HTML-only body.
func stripHTMLTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
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

// BackfillSummaries populates the summary columns for rows the forward fold
// already passed but that predate those columns (summary_folded=false with
// createseq <= cursor) — i.e. every row on an in-place upgrade, since the thread
// cursor is already at head so DrainAccount never revisits them. It re-parses
// each such row and writes the summary columns (leaving thread_id as-is, which is
// already correct), marking summary_folded=true. Idempotent and bounded per call;
// once every legacy row is backfilled it becomes a no-op. Without this, filtered
// search would silently omit all pre-existing mail (its search columns stay ”).
func (w *ThreadWorker) BackfillSummaries(ctx context.Context, tenantID, accountID int64) error {
	batch := w.Batch
	if batch <= 0 {
		batch = 100
	}
	for {
		rows, err := w.Pool.Query(ctx,
			`SELECT id, blob_ref, msg_prefix FROM messages
			 WHERE account_id=$1 AND NOT summary_folded
			 ORDER BY id LIMIT $2`, accountID, batch)
		if err != nil {
			return err
		}
		type row struct {
			id      int64
			blobRef string
			prefix  []byte
		}
		var todo []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.blobRef, &r.prefix); err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(todo) == 0 {
			return nil
		}
		for _, r := range todo {
			_, sum, err := w.parseMessage(ctx, tenantID, r.blobRef, r.prefix)
			if err != nil {
				return err
			}
			if _, err := w.Pool.Exec(ctx,
				`UPDATE messages SET subject=$2, from_addr=$3, to_addrs=$4,
				   from_search=$5, to_search=$6, preview=$7, summary_folded=true
				 WHERE id=$1 AND account_id=$8`,
				r.id, sum.subject, sum.from, sum.to, sum.fromSearch, sum.toSearch, sum.preview, accountID); err != nil {
				return err
			}
		}
	}
}

// RebuildAccount clears thread_id + thread_refs and resets the cursor, re-folding
// the whole log from seq 0.
func (w *ThreadWorker) RebuildAccount(ctx context.Context, tenantID, accountID int64) error {
	if _, err := w.Pool.Exec(ctx,
		`UPDATE messages SET thread_id=NULL, summary_folded=false,
		   subject='', from_addr='', to_addrs='', from_search='', to_search='', preview=''
		 WHERE account_id=$1`, accountID); err != nil {
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
