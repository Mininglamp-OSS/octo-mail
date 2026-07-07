package postgres

import (
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// Tx methods: Get/Insert/Update/Delete operate on shape types by primary key /
// simple upsert. For P1 the protocol read paths mostly use the query builders.

func (pt *pgTx) Get(v any) error {
	switch x := v.(type) {
	case *store.Mailbox:
		row := pt.tx.QueryRow(pt.ctx, `SELECT `+mailboxCols+` FROM mailboxes WHERE id=$1 AND account_id=$2`, x.ID, pt.acc.id)
		mb, err := scanMailbox(row)
		if err == pgx.ErrNoRows {
			return errNotFound
		}
		if err != nil {
			return err
		}
		*x = mb
		return nil
	case *store.Message:
		m, err := pt.getMessage(x.ID)
		if err != nil {
			return err
		}
		*x = m
		return nil
	default:
		return errUnknownChange
	}
}

func (pt *pgTx) Insert(v any) error { return errNotFound } // handled by MessageAdd/ensureMailbox
func (pt *pgTx) Delete(v any) error { return errNotFound }

func (pt *pgTx) Update(v any) error {
	switch x := v.(type) {
	case *store.Message:
		seq := pt.nextModSeq()
		x.ModSeq = seq
		// Read the prior seen state (account-scoped) so we can adjust the mailbox
		// unseen/unread counters by the delta. This SELECT also doubles as the
		// existence+ownership check (fail closed on a foreign/missing id).
		var oldSeen bool
		if err := pt.tx.QueryRow(pt.ctx,
			`SELECT f_seen FROM messages WHERE id=$1 AND account_id=$2`,
			x.ID, pt.acc.id).Scan(&oldSeen); err != nil {
			if err == pgx.ErrNoRows {
				return errNotFound
			}
			return err
		}
		ct, err := pt.tx.Exec(pt.ctx,
			`UPDATE messages SET f_seen=$2,f_answered=$3,f_flagged=$4,f_forwarded=$5,f_junk=$6,
				f_notjunk=$7,f_deleted=$8,f_draft=$9,f_phishing=$10,f_mdnsent=$11,keywords=$12,modseq=$13
			 WHERE id=$1 AND account_id=$14`,
			x.ID, x.Seen, x.Answered, x.Flagged, x.Forwarded, x.Junk, x.Notjunk, x.Deleted, x.Draft,
			x.Phishing, x.MDNSent, x.Keywords, int64(seq), pt.acc.id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return errNotFound
		}
		// Keep the mailbox unseen/unread projection in step with the flag change —
		// otherwise IMAP STATUS(UNSEEN) and JMAP unreadEmails drift on the commonest
		// operation (mark-read). unseen and unread share one counter. c_deleted is
		// intentionally NOT maintained here: it has no reader (IMAP STATUS(DELETED)
		// recomputes by scanning) and MessageRemove doesn't decrement it, so bumping
		// it on Update would drift it upward asymmetrically.
		dUnseen := boolInt(!x.Seen) - boolInt(!oldSeen)
		if dUnseen != 0 {
			if err := pt.bumpCounts(x.MailboxID, 0, 0, dUnseen, 0); err != nil {
				return err
			}
		}
		return pt.record(store.ChangeFlags{
			MailboxID: x.MailboxID, UID: x.UID, ModSeq: seq, Flags: x.Flags, Mask: x.Flags, Keywords: x.Keywords,
		})
	default:
		return errUnknownChange
	}
}

func (pt *pgTx) getMessage(id int64) (store.Message, error) {
	row := pt.tx.QueryRow(pt.ctx, `SELECT `+messageCols+` FROM messages WHERE id=$1 AND account_id=$2`, id, pt.acc.id)
	return scanMessage(row)
}

const messageCols = `id, account_id, mailbox_id, uid, createseq, modseq, expunged,
	f_seen, f_answered, f_flagged, f_forwarded, f_junk, f_notjunk, f_deleted, f_draft, f_phishing, f_mdnsent,
	keywords, blob_ref, size, thread_id, email_id, received_at, save_date, msg_prefix`

func scanMessage(row pgx.Row) (store.Message, error) {
	var m store.Message
	var thread *int64
	var emailID *int64
	err := row.Scan(&m.ID, &m.AccountID, &m.MailboxID, &m.UID, &m.CreateSeq, &m.ModSeq, &m.Expunged,
		&m.Seen, &m.Answered, &m.Flagged, &m.Forwarded, &m.Junk, &m.Notjunk, &m.Deleted, &m.Draft, &m.Phishing, &m.MDNSent,
		&m.Keywords, &m.BlobRef, &m.Size, &thread, &emailID, &m.Received, &m.SaveDate, &m.MsgPrefix)
	if err != nil {
		return store.Message{}, err
	}
	if thread != nil {
		m.ThreadID = *thread
	}
	if emailID != nil {
		m.EmailID = *emailID
	}
	return m, nil
}

// --- MessageQuery: the bounded SQL builder replacing bstore.QueryTx[Message] ---

func (pt *pgTx) QueryMessage() store.MessageQuery {
	// Isolation is structural, not a caller convention: every message query is
	// unconditionally constrained to this tx's account. A caller-supplied
	// mailbox/uid id that belongs to another account simply matches no rows —
	// there is no way to widen the query past the account boundary.
	return (&msgQuery{pt: pt}).add("account_id=", pt.acc.id)
}

type msgQuery struct {
	pt     *pgTx
	wheres []string
	args   []any
	order  string
	limit  int
}

func (q *msgQuery) add(cond string, arg any) *msgQuery {
	q.args = append(q.args, arg)
	q.wheres = append(q.wheres, cond+"$"+itoaPos(len(q.args)))
	return q
}

func (q *msgQuery) FilterMailbox(id int64) store.MessageQuery { return q.add("mailbox_id=", id) }
func (q *msgQuery) FilterModSeqGreater(m store.ModSeq) store.MessageQuery {
	return q.add("modseq>", int64(m))
}
func (q *msgQuery) FilterUIDRange(lo, hi store.UID) store.MessageQuery {
	q.add("uid>=", int64(lo))
	return q.add("uid<=", int64(hi))
}
func (q *msgQuery) FilterFlags(mask, want store.Flags) store.MessageQuery {
	// P1: only \Seen filtering is commonly needed; extend as required.
	if mask.Seen {
		return q.add("f_seen=", want.Seen)
	}
	return q
}
func (q *msgQuery) FilterFTS(query string) store.MessageQuery {
	// Match messages whose fts tsvector matches the query. The fts projection is
	// async, so very recently delivered messages may not yet be indexed — that is
	// the tolerated staleness of a non-read-your-write projection.
	q.args = append(q.args, query)
	pos := "$" + itoaPos(len(q.args))
	q.wheres = append(q.wheres,
		"id IN (SELECT message_id FROM fts WHERE account_id=messages.account_id AND tsv @@ plainto_tsquery('simple', "+pos+"))")
	return q
}
func (q *msgQuery) SortUID() store.MessageQuery    { q.order = " ORDER BY uid"; return q }
func (q *msgQuery) Limit(n int) store.MessageQuery { q.limit = n; return q }

func (q *msgQuery) sql() string {
	sb := strings.Builder{}
	sb.WriteString(`SELECT ` + messageCols + ` FROM messages WHERE NOT expunged`)
	for _, w := range q.wheres {
		sb.WriteString(" AND " + w)
	}
	sb.WriteString(q.order)
	if q.limit > 0 {
		sb.WriteString(" LIMIT " + strconv.Itoa(q.limit))
	}
	return sb.String()
}

func (q *msgQuery) ForEach(fn func(store.Message) error) error {
	rows, err := q.pt.tx.Query(q.pt.ctx, q.sql(), q.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return err
		}
		if err := fn(m); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (q *msgQuery) List() ([]store.Message, error) {
	var out []store.Message
	err := q.ForEach(func(m store.Message) error { out = append(out, m); return nil })
	return out, err
}

func (q *msgQuery) Count() (int, error) {
	n := 0
	err := q.ForEach(func(store.Message) error { n++; return nil })
	return n, err
}

// --- MailboxQuery ---

func (pt *pgTx) QueryMailbox() store.MailboxQuery {
	return &mbQuery{pt: pt, includeExpunged: false}
}

type mbQuery struct {
	pt              *pgTx
	includeExpunged bool
}

func (q *mbQuery) FilterExpunged(b bool) store.MailboxQuery { q.includeExpunged = b; return q }

func (q *mbQuery) ForEach(fn func(store.Mailbox) error) error {
	sql := `SELECT ` + mailboxCols + ` FROM mailboxes WHERE account_id=$1`
	if !q.includeExpunged {
		sql += ` AND NOT expunged`
	}
	sql += ` ORDER BY name`
	rows, err := q.pt.tx.Query(q.pt.ctx, sql, q.pt.acc.id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		mb, err := scanMailbox(rows)
		if err != nil {
			return err
		}
		if err := fn(mb); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (q *mbQuery) List() ([]store.Mailbox, error) {
	var out []store.Mailbox
	err := q.ForEach(func(mb store.Mailbox) error { out = append(out, mb); return nil })
	return out, err
}

func itoaPos(n int) string { return strconv.Itoa(n) }
