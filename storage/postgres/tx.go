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
	keywords, blob_ref, size, thread_id, email_id, received_at, save_date, msg_prefix,
	subject, from_addr, to_addrs, from_search, to_search, preview, summary_folded`

func scanMessage(row pgx.Row) (store.Message, error) {
	var m store.Message
	var thread *int64
	var emailID *int64
	err := row.Scan(&m.ID, &m.AccountID, &m.MailboxID, &m.UID, &m.CreateSeq, &m.ModSeq, &m.Expunged,
		&m.Seen, &m.Answered, &m.Flagged, &m.Forwarded, &m.Junk, &m.Notjunk, &m.Deleted, &m.Draft, &m.Phishing, &m.MDNSent,
		&m.Keywords, &m.BlobRef, &m.Size, &thread, &emailID, &m.Received, &m.SaveDate, &m.MsgPrefix,
		&m.Subject, &m.FromAddr, &m.ToAddrs, &m.FromSearch, &m.ToSearch, &m.Preview, &m.SummaryFolded)
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
	pt       *pgTx
	wheres   []string
	args     []any
	order    string
	limit    int
	offset   int
	distinct bool // collapse sibling rows of one Email (DISTINCT ON email group)
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
func (q *msgQuery) FilterThread(id int64) store.MessageQuery { return q.add("thread_id=", id) }
func (q *msgQuery) FilterUnfolded() store.MessageQuery {
	q.wheres = append(q.wheres, "NOT summary_folded")
	return q
}
func (q *msgQuery) FilterFolded() store.MessageQuery {
	q.wheres = append(q.wheres, "summary_folded")
	return q
}

// ilikeContains adds a case-insensitive substring match on col, escaping the
// LIKE metacharacters %, _ and \ in the user input so they match literally.
func (q *msgQuery) ilikeContains(col, substr string) *msgQuery {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(substr)
	q.args = append(q.args, "%"+esc+"%")
	q.wheres = append(q.wheres, col+" ILIKE $"+itoaPos(len(q.args))+` ESCAPE '\'`)
	return q
}
func (q *msgQuery) FilterSubject(substr string) store.MessageQuery {
	return q.ilikeContains("subject", substr)
}
func (q *msgQuery) FilterFrom(substr string) store.MessageQuery {
	return q.ilikeContains("from_search", substr)
}
func (q *msgQuery) FilterTo(substr string) store.MessageQuery {
	return q.ilikeContains("to_search", substr)
}
func (q *msgQuery) FilterReceivedRange(after, before string) store.MessageQuery {
	if after != "" {
		q.add("received_at>=", after)
	}
	if before != "" {
		q.add("received_at<", before)
	}
	return q
}
func (q *msgQuery) FilterSizeRange(min, max int64) store.MessageQuery {
	if min > 0 {
		q.add("size>=", min)
	}
	if max > 0 {
		q.add("size<=", max)
	}
	return q
}
func (q *msgQuery) FilterKeyword(kw string, want bool) store.MessageQuery {
	// System flags map to their f_* columns; anything else is a custom keyword in
	// the keywords array (matched case-insensitively, as the JMAP filter did).
	if col, ok := systemFlagColumn(kw); ok {
		return q.add(col+"=", want)
	}
	q.args = append(q.args, kw)
	pos := "$" + itoaPos(len(q.args))
	cond := "EXISTS (SELECT 1 FROM unnest(keywords) k WHERE lower(k)=lower(" + pos + "))"
	if !want {
		cond = "NOT " + cond
	}
	q.wheres = append(q.wheres, cond)
	return q
}
func (q *msgQuery) SortUID() store.MessageQuery { q.order = " ORDER BY uid"; return q }
func (q *msgQuery) SortReceivedDesc() store.MessageQuery {
	// received_at DESC, id DESC — a total order (id breaks received-time ties), so
	// LIMIT/OFFSET paging is stable (index: messages_received_idx).
	q.order = " ORDER BY received_at DESC, id DESC"
	return q
}
func (q *msgQuery) SortReceivedAsc() store.MessageQuery {
	q.order = " ORDER BY received_at ASC, id ASC"
	return q
}
func (q *msgQuery) SortSizeDesc() store.MessageQuery {
	q.order = " ORDER BY size DESC, id DESC"
	return q
}
func (q *msgQuery) SortSizeAsc() store.MessageQuery {
	q.order = " ORDER BY size ASC, id ASC"
	return q
}
func (q *msgQuery) DistinctEmail() store.MessageQuery { q.distinct = true; return q }
func (q *msgQuery) Limit(n int) store.MessageQuery    { q.limit = n; return q }
func (q *msgQuery) Offset(n int) store.MessageQuery   { q.offset = n; return q }

// systemFlagColumn maps an IMAP/JMAP system-flag keyword to its f_* column. The
// keyword is matched case-insensitively (matching the prior Go filter), covering
// both the JMAP "$seen" and IMAP "\Seen" spellings.
func systemFlagColumn(kw string) (string, bool) {
	switch strings.ToLower(kw) {
	case `\seen`, "$seen":
		return "f_seen", true
	case `\answered`, "$answered":
		return "f_answered", true
	case `\flagged`, "$flagged":
		return "f_flagged", true
	case `\draft`, "$draft":
		return "f_draft", true
	case `\deleted`, "$deleted":
		return "f_deleted", true
	case `\junk`, "$junk":
		return "f_junk", true
	}
	return "", false
}

// selectBody builds "col... FROM messages WHERE ..." shared by List/Count.
func (q *msgQuery) whereClause() string {
	sb := strings.Builder{}
	sb.WriteString(" FROM messages WHERE NOT expunged")
	for _, w := range q.wheres {
		sb.WriteString(" AND " + w)
	}
	return sb.String()
}

// emailGroupExpr is the JMAP Email identity of a row: its email_id group, or its
// own id when it isn't a sibling. Used for DISTINCT ON dedup.
const emailGroupExpr = "COALESCE(email_id, id)"

func (q *msgQuery) sql() string {
	if q.distinct {
		// Collapse sibling rows of one Email to a single representative, then apply
		// the caller's sort + paging over the deduped set. DISTINCT ON requires its
		// key to lead ORDER BY, so dedup happens in an inner query (keeping the
		// lowest id per group for determinism) and the outer query re-sorts/pages.
		inner := "SELECT DISTINCT ON (" + emailGroupExpr + ") " + messageCols +
			q.whereClause() + " ORDER BY " + emailGroupExpr + ", id"
		sb := strings.Builder{}
		sb.WriteString("SELECT * FROM (" + inner + ") t")
		sb.WriteString(q.order)
		if q.limit > 0 {
			sb.WriteString(" LIMIT " + strconv.Itoa(q.limit))
		}
		if q.offset > 0 {
			sb.WriteString(" OFFSET " + strconv.Itoa(q.offset))
		}
		return sb.String()
	}
	sb := strings.Builder{}
	sb.WriteString("SELECT " + messageCols + q.whereClause())
	sb.WriteString(q.order)
	if q.limit > 0 {
		sb.WriteString(" LIMIT " + strconv.Itoa(q.limit))
	}
	if q.offset > 0 {
		sb.WriteString(" OFFSET " + strconv.Itoa(q.offset))
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
	// Count ignores order/limit/offset. With DistinctEmail, count distinct Email
	// groups; otherwise count rows. This is the accurate total for a filtered set,
	// independent of the page window a caller may also request.
	var sqlStr string
	if q.distinct {
		sqlStr = "SELECT count(DISTINCT " + emailGroupExpr + ")" + q.whereClause()
	} else {
		sqlStr = "SELECT count(*)" + q.whereClause()
	}
	var n int
	if err := q.pt.tx.QueryRow(q.pt.ctx, sqlStr, q.args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
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
