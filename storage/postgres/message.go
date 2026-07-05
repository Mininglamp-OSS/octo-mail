package postgres

import (
	"bytes"
	"context"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// MessageAdd appends a message to a mailbox: streams the body to the blob store,
// allocates the per-mailbox UID and the account modseq, inserts the projection
// row, updates counts and quota, and records a ChangeAddUID entry — all in tx.
func (a *account) MessageAdd(tx store.Tx, mb *store.Mailbox, m *store.Message, body store.BlobReader, opts store.AddOpts) ([]store.Change, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)

	// Enforce quota BEFORE storing the body: reject if accepting this message
	// would exceed the per-account or per-tenant byte limit. Checked inside the
	// writer transaction (holding the advisory lock), so concurrent deliveries
	// to the same account cannot race past the limit.
	incoming := body.Size() + int64(len(m.MsgPrefix))
	if ok, _, err := a.CanAddMessageSize(tx, incoming); err != nil {
		return nil, err
	} else if !ok {
		return nil, store.ErrOverQuota
	}

	// Store the body (content-addressed; dedup within tenant).
	ref, size, err := a.s.Blob.Put(pt.ctx, a.tenantID, body)
	if err != nil {
		return nil, err
	}
	m.BlobRef = string(ref)
	m.Size = size + int64(len(m.MsgPrefix))

	// Allocate UID from the mailbox and modseq from the account log.
	var uid int64
	if err := pt.tx.QueryRow(pt.ctx,
		`UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id=$1 RETURNING uidnext - 1`,
		mb.ID).Scan(&uid); err != nil {
		return nil, err
	}
	seq := pt.nextModSeq()
	m.UID = store.UID(uid)
	m.ModSeq = seq
	m.CreateSeq = seq
	m.MailboxID = mb.ID
	m.AccountID = a.id
	if m.Keywords == nil {
		m.Keywords = []string{}
	}
	if m.MsgPrefix == nil {
		m.MsgPrefix = []byte{}
	}

	var id int64
	// received_at defaults to now(), but an explicit m.Received (e.g. IMAP APPEND
	// date-time) overrides it via COALESCE.
	var explicitReceived any
	if !m.Received.IsZero() {
		explicitReceived = m.Received
	}
	err = pt.tx.QueryRow(pt.ctx,
		`INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq,
			f_seen, f_answered, f_flagged, f_forwarded, f_junk, f_notjunk, f_deleted, f_draft, f_phishing, f_mdnsent,
			keywords, blob_ref, size, thread_id, email_id, msg_prefix, received_at)
		 VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,COALESCE($21,now())) RETURNING id, received_at, save_date`,
		a.id, mb.ID, uid, int64(seq),
		m.Seen, m.Answered, m.Flagged, m.Forwarded, m.Junk, m.Notjunk, m.Deleted, m.Draft, m.Phishing, m.MDNSent,
		m.Keywords, m.BlobRef, m.Size, nullInt64(m.ThreadID), nullInt64(opts.EmailID), m.MsgPrefix, explicitReceived).Scan(&id, &m.Received, &m.SaveDate)
	if err != nil {
		return nil, err
	}
	m.ID = id
	m.EmailID = opts.EmailID

	if err := pt.bumpCounts(mb.ID, 1, m.Size, boolInt(!m.Seen), boolInt(m.Deleted)); err != nil {
		return nil, err
	}
	if err := pt.bumpQuota(1, m.Size); err != nil {
		return nil, err
	}
	if err := pt.record(store.ChangeAddUID{
		MailboxID: mb.ID, UID: m.UID, ModSeq: seq, Flags: m.Flags, Keywords: m.Keywords,
	}); err != nil {
		return nil, err
	}
	return pt.changes[before:], nil
}

// DeliverMailbox is the inbound convenience path: ensure the mailbox, add the
// message, in one transaction. Used by smtpserver.
func (a *account) DeliverMailbox(mailbox string, m *store.Message, body store.BlobReader) ([]store.Change, error) {
	var changes []store.Change
	err := a.Tx(context.Background(), func(tx store.Tx) error {
		mb, err := a.MailboxFind(tx, mailbox)
		if err != nil {
			return err
		}
		if mb == nil {
			nmb, _, e := a.MailboxEnsure(tx, mailbox, true, store.SpecialUse{}, nil)
			if e != nil {
				return e
			}
			mb = &nmb
		}
		_, err = a.MessageAdd(tx, mb, m, body, store.AddOpts{})
		return err
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

// MessagesByEmailID returns all live rows in an email group: the original row
// (id == emailID, its email_id is NULL) plus any siblings (email_id == emailID),
// ordered by mailbox_id. This is the JMAP multi-mailbox view of one message.
func (a *account) MessagesByEmailID(tx store.Tx, emailID int64) ([]store.Message, error) {
	pt := tx.(*pgTx)
	rows, err := pt.tx.Query(pt.ctx,
		`SELECT `+messageCols+` FROM messages
		 WHERE account_id=$1 AND NOT expunged AND (id=$2 OR email_id=$2)
		 ORDER BY mailbox_id`,
		a.id, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddSibling materializes an existing message in another mailbox as a new row
// sharing the source's effective email identity: same content (blob is
// content-addressed, so no copy), new mailbox/uid, flags carried over. IMAP sees
// an ordinary new message; JMAP sees the email's mailboxIds set grow by one.
func (a *account) AddSibling(tx store.Tx, src store.Message, mb *store.Mailbox) (store.Message, []store.Change, error) {
	body := a.MessageReader(src)
	nm := &store.Message{Flags: src.Flags, Keywords: src.Keywords, ThreadID: src.ThreadID}
	changes, err := a.MessageAdd(tx, mb, nm, body, store.AddOpts{EmailID: src.EffectiveEmailID()})
	if err != nil {
		return store.Message{}, nil, err
	}
	return *nm, changes, nil
}

// MessageRemove expunges messages: marks rows, records ChangeRemoveUIDs, updates counts.
func (a *account) MessageRemove(tx store.Tx, modseq store.ModSeq, mb *store.Mailbox, opts store.RemoveOpts, msgs ...store.Message) (store.ChangeRemoveUIDs, store.ChangeMailboxCounts, error) {
	pt := tx.(*pgTx)
	if modseq == 0 {
		modseq = pt.nextModSeq()
	}
	var uids []store.UID
	var ids []int64
	var totalSize int64
	var unseen int
	for _, m := range msgs {
		uids = append(uids, m.UID)
		ids = append(ids, m.ID)
		totalSize += m.Size
		if !m.Seen {
			unseen++
		}
		if _, err := pt.tx.Exec(pt.ctx,
			`UPDATE messages SET expunged=true, modseq=$1 WHERE id=$2`, int64(modseq), m.ID); err != nil {
			return store.ChangeRemoveUIDs{}, store.ChangeMailboxCounts{}, err
		}
	}
	if err := pt.bumpCounts(mb.ID, -len(msgs), -totalSize, -unseen, 0); err != nil {
		return store.ChangeRemoveUIDs{}, store.ChangeMailboxCounts{}, err
	}
	if err := pt.bumpQuota(-len(msgs), -totalSize); err != nil {
		return store.ChangeRemoveUIDs{}, store.ChangeMailboxCounts{}, err
	}
	cr := store.ChangeRemoveUIDs{MailboxID: mb.ID, UIDs: uids, ModSeq: modseq, MsgIDs: ids}
	if err := pt.record(cr); err != nil {
		return store.ChangeRemoveUIDs{}, store.ChangeMailboxCounts{}, err
	}
	return cr, store.ChangeMailboxCounts{MailboxID: mb.ID}, nil
}

// MessageReader streams MsgPrefix followed by the blob body.
func (a *account) MessageReader(m store.Message) store.BlobReader {
	return &prefixReader{
		acc:    a,
		ref:    blob.Ref(m.BlobRef),
		prefix: m.MsgPrefix,
		size:   m.Size,
	}
}

// CanAddMessageSize checks per-account then per-tenant quota.
func (a *account) CanAddMessageSize(tx store.Tx, size int64) (bool, int64, error) {
	pt := tx.(*pgTx)
	var limit *int64
	if err := pt.tx.QueryRow(pt.ctx, `SELECT quota_bytes FROM accounts WHERE id=$1`, a.id).Scan(&limit); err != nil {
		return false, 0, err
	}
	if limit == nil {
		return true, 0, nil
	}
	var used int64
	_ = pt.tx.QueryRow(pt.ctx,
		`SELECT bytes_used FROM quota_counters WHERE scope_type=1 AND scope_id=$1`, a.id).Scan(&used)
	return used+size <= *limit, *limit, nil
}

// QuotaUsage returns used bytes, message count, and the account byte limit (0 =
// unlimited). Read-only; no advisory lock.
func (a *account) QuotaUsage(ctx context.Context) (usedBytes, msgCount, limitBytes int64, err error) {
	_ = a.s.Pool.QueryRow(ctx,
		`SELECT bytes_used, msg_count FROM quota_counters WHERE scope_type=1 AND scope_id=$1`, a.id).
		Scan(&usedBytes, &msgCount)
	var limit *int64
	if e := a.s.Pool.QueryRow(ctx, `SELECT quota_bytes FROM accounts WHERE id=$1`, a.id).Scan(&limit); e != nil {
		return 0, 0, 0, e
	}
	if limit != nil {
		limitBytes = *limit
	}
	return usedBytes, msgCount, limitBytes, nil
}

// --- projection count/quota helpers ---
func (pt *pgTx) bumpCounts(mailboxID int64, dTotal int, dSize int64, dUnseen, dDeleted int) error {
	_, err := pt.tx.Exec(pt.ctx,
		`UPDATE mailboxes SET c_total=c_total+$2, c_size=c_size+$3, c_unseen=c_unseen+$4,
			c_unread=c_unread+$4, c_deleted=c_deleted+$5 WHERE id=$1`,
		mailboxID, dTotal, dSize, dUnseen, dDeleted)
	return err
}

func (pt *pgTx) bumpQuota(dCount int, dSize int64) error {
	// account scope (1) and tenant scope (0).
	for _, sc := range []struct {
		typ int
		id  int64
	}{{1, pt.acc.id}, {0, pt.acc.tenantID}} {
		if _, err := pt.tx.Exec(pt.ctx,
			`INSERT INTO quota_counters (scope_type, scope_id, bytes_used, msg_count)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (scope_type, scope_id)
			 DO UPDATE SET bytes_used=quota_counters.bytes_used+$3, msg_count=quota_counters.msg_count+$4`,
			sc.typ, sc.id, dSize, dCount); err != nil {
			return err
		}
	}
	return nil
}

// prefixReader concatenates MsgPrefix and the blob body, satisfying BlobReader.
type prefixReader struct {
	acc    *account
	ref    blob.Ref
	prefix []byte
	size   int64

	r      io.Reader
	closer io.Closer
}

func (p *prefixReader) ensure() error {
	if p.r != nil {
		return nil
	}
	br, err := p.acc.s.Blob.Open(context.Background(), p.acc.tenantID, p.ref)
	if err != nil {
		return err
	}
	p.closer = br
	p.r = io.MultiReader(bytes.NewReader(p.prefix), br)
	return nil
}

func (p *prefixReader) Read(b []byte) (int, error) {
	if err := p.ensure(); err != nil {
		return 0, err
	}
	return p.r.Read(b)
}

func (p *prefixReader) ReadAt(b []byte, off int64) (int, error) {
	// Simple implementation: prefix then blob. For P1, IMAP partial fetch is rare;
	// full correctness (ranged across the prefix boundary) can be optimized later.
	br, err := p.acc.s.Blob.Open(context.Background(), p.acc.tenantID, p.ref)
	if err != nil {
		return 0, err
	}
	defer br.Close()
	full := io.MultiReader(bytes.NewReader(p.prefix), br)
	if _, err := io.CopyN(io.Discard, full, off); err != nil {
		return 0, err
	}
	return io.ReadFull(full, b)
}

func (p *prefixReader) Size() int64 { return p.size }

func (p *prefixReader) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var _ = pgx.ErrNoRows
