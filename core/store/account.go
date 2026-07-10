package store

import (
	"context"
	"errors"
	"io"
)

// ErrOverQuota is returned by delivery/append paths when accepting a message
// would exceed the per-account or per-tenant byte quota. It is a permanent
// condition (the message is rejected, not deferred).
var ErrOverQuota = errors.New("over quota")

// AddOpts controls MessageAdd behavior.
type AddOpts struct {
	Train bool // Whether to train the junk filter.

	// EmailID, when non-zero, marks this row as a sibling of an existing email
	// (same content, another mailbox) in the JMAP multi-mailbox model. The row
	// gets its own mailbox/uid/flags but shares this email identity. Zero = the
	// row is its own email.
	EmailID int64
}

// RemoveOpts controls MessageRemove behavior.
type RemoveOpts struct {
	Expunge bool
}

// BlobReader streams a message body from the blob store. It is an io.ReadCloser
// and, where the backend supports it, an io.ReaderAt for ranged FETCH BODY[].
type BlobReader interface {
	io.ReadCloser
	io.ReaderAt
	Size() int64
}

// Account is the unit of storage isolation: one mailbox tree, one change-log.
// Handles are obtained only through the Directory object graph (a TenantScope or
// an InboundTarget), never by global name — this is what makes tenant isolation
// structural rather than a per-query discipline.
//
// The method set is exactly what the reused protocol handlers call. Writer
// serialization for an account is provided by Tx, which on the Postgres backend
// takes a transaction-scoped advisory lock so ordering holds across stateless
// nodes; there is no separate in-process lock to acquire.
type Account interface {
	ID() int64

	// TenantID returns the id of the tenant this account belongs to. Used to
	// scope tenant-shared resources (e.g. the content-addressed blob store) to
	// the authenticated tenant, so a client-supplied id can never name another
	// tenant's namespace.
	TenantID() int64

	// Tx runs fn in a database transaction (read-write). The advisory writer
	// lock is taken inside write transactions.
	Tx(ctx context.Context, fn func(Tx) error) error

	// ReadTx runs fn in a read-only transaction: no advisory lock (concurrent
	// reads don't serialize), a single MVCC snapshot, and no changelog flush or
	// publish. fn must not mutate — the backend opens it read-only. Use for pure
	// reads (IMAP FETCH/SEARCH/STATUS/SORT, read-only JMAP/webapi GETs).
	ReadTx(ctx context.Context, fn func(Tx) error) error

	// NextModSeq returns the next account log offset (= changelog_seq + 1).
	NextModSeq(tx Tx) (ModSeq, error)
	NextUIDValidity(tx Tx) (uint32, error)

	// ChangelogHead returns the current account log head (= max assigned seq)
	// without mutating it. This is the JMAP state / IMAP HIGHESTMODSEQ.
	ChangelogHead(ctx context.Context) (ModSeq, error)

	// MessageCount returns the non-expunged message count of a mailbox via a
	// lightweight read (no advisory lock). Used by IMAP IDLE to emit EXISTS.
	MessageCount(ctx context.Context, mailboxID int64) int

	// URLAuthKey returns the mailbox's URLAUTH (RFC 4467) access key, creating a
	// random one on first use. URLAuthResetKey rotates one mailbox's key;
	// URLAuthResetAll drops every key for the account. Rotating a key revokes all
	// URLs previously authorized against that mailbox.
	URLAuthKey(ctx context.Context, mailboxID int64) ([]byte, error)
	URLAuthResetKey(ctx context.Context, mailboxID int64) ([]byte, error)
	URLAuthResetAll(ctx context.Context) error

	// ExpungedUIDsSince returns the UIDs expunged from a mailbox in change-log
	// entries with seq > since, in increasing UID order. This is the history
	// IMAP QRESYNC needs to synthesize a VANISHED (EARLIER) response: the
	// change-log is the durable record of what was removed and when (by modseq).
	ExpungedUIDsSince(ctx context.Context, mailboxID int64, since ModSeq) ([]UID, error)

	// AnnotationSet stores (or, with value=nil, removes) an IMAP METADATA entry
	// for a mailbox (mailboxID=0 for a server entry). Records a ChangeAnnotation.
	AnnotationSet(ctx context.Context, mailboxID int64, key string, value []byte, isString bool) error
	// AnnotationList returns the annotations for a mailbox (mailboxID=0 for server
	// entries) whose key is at or below any of the given prefixes (empty = all).
	AnnotationList(ctx context.Context, mailboxID int64, prefixes []string) ([]Annotation, error)

	// VacationGet returns the account's JMAP vacation response (ok=false if none
	// stored yet — treated as a disabled default).
	VacationGet(ctx context.Context) (VacationResponse, bool, error)
	// VacationSet upserts the account's vacation response.
	VacationSet(ctx context.Context, v VacationResponse) error
	// VacationShouldReply atomically records that an auto-reply is being sent to
	// sender and returns true only the first time within the dedup window (so a
	// vacation reply goes out at most once per sender). Returns false if already
	// replied.
	VacationShouldReply(ctx context.Context, sender string) (bool, error)

	MailboxFind(tx Tx, name string) (*Mailbox, error)
	MailboxEnsure(tx Tx, name string, subscribe bool, su SpecialUse, modseq *ModSeq) (Mailbox, []Change, error)
	MailboxCreate(tx Tx, name string, su SpecialUse) (mb Mailbox, changes []Change, created []string, exists bool, err error)
	MailboxRename(tx Tx, src *Mailbox, dst string, modseq *ModSeq) (changes []Change, alreadyExists, notExists bool, err error)
	MailboxDelete(ctx context.Context, tx Tx, mb *Mailbox) (changes []Change, hasChildren bool, err error)

	SubscriptionEnsure(tx Tx, name string) ([]Change, error)
	SubscriptionRemove(tx Tx, name string) ([]Change, error)

	// MessageAdd appends a message: streams body to blobs, appends a
	// ChangeAddUID entry, updates projections — all in tx.
	MessageAdd(tx Tx, mb *Mailbox, m *Message, body BlobReader, opts AddOpts) ([]Change, error)
	// DeliverMailbox is the inbound convenience path used by smtpserver.
	DeliverMailbox(ctx context.Context, mailbox string, m *Message, body BlobReader) ([]Change, error)
	MessageRemove(tx Tx, modseq ModSeq, mb *Mailbox, opts RemoveOpts, msgs ...Message) (ChangeRemoveUIDs, ChangeMailboxCounts, error)

	// MessagesByEmailID returns all live rows sharing an effective email identity
	// (the JMAP multi-mailbox group): the original row whose id == emailID, plus
	// any sibling rows whose email_id == emailID. Ordered by mailbox_id. Used by
	// JMAP to present one Email object with a mailboxIds set spanning folders.
	MessagesByEmailID(tx Tx, emailID int64) ([]Message, error)

	// AddSibling copies an existing message into another mailbox as a new row that
	// shares the source's effective email identity (same blob, new mailbox/uid/
	// flags). This is how a JMAP Email/set that adds a mailboxId materializes the
	// membership while keeping IMAP's one-row-per-(mailbox,uid) model. Returns the
	// new row and the emitted changes.
	AddSibling(tx Tx, src Message, mb *Mailbox) (Message, []Change, error)

	// MessageReader streams a message body (MsgPrefix + blob) from the blob store.
	// ctx bounds the underlying blob reads (cancellation/deadline).
	MessageReader(ctx context.Context, m Message) BlobReader

	// CanAddMessageSize checks per-account and per-tenant quota.
	CanAddMessageSize(tx Tx, size int64) (ok bool, maxSize int64, err error)

	// QuotaUsage returns the account's used bytes and message count, and the byte
	// limit (0 = unlimited). Read-only, for IMAP GETQUOTA.
	QuotaUsage(ctx context.Context) (usedBytes, msgCount, limitBytes int64, err error)

	// RegisterComm subscribes to this account's change stream (IMAP IDLE, JMAP
	// push). On multi-node it is backed by the coordinator (LISTEN/NOTIFY).
	RegisterComm() *Comm

	Close() error
}

// Tx is a storage transaction. Get/Insert/Update/Delete operate on the shape
// types (Mailbox, Message, ...). Query builders cover the IMAP FETCH/SEARCH and
// JMAP query shapes without leaking the underlying engine.
type Tx interface {
	Get(v any) error
	Insert(v any) error
	Update(v any) error
	Delete(v any) error

	QueryMessage() MessageQuery
	QueryMailbox() MailboxQuery
}

// MessageQuery is the bounded query surface the protocol code needs: FETCH by
// UID range, CONDSTORE CHANGEDSINCE, flag filters, and full-text SEARCH. This is
// the single seam that replaces the bstore.QueryTx[Message] generic.
type MessageQuery interface {
	FilterMailbox(id int64) MessageQuery
	FilterUIDRange(lo, hi UID) MessageQuery
	FilterModSeqGreater(m ModSeq) MessageQuery
	FilterFlags(mask, want Flags) MessageQuery
	FilterFTS(query string) MessageQuery
	// FilterThread restricts to messages in the given thread (indexed).
	FilterThread(id int64) MessageQuery
	// FilterUnfolded restricts to rows the summary projection has not yet folded
	// (summary_folded=false) — a small, recent set. Used to evaluate header
	// filters live against just-delivered mail so filtered search isn't stale.
	FilterUnfolded() MessageQuery
	// FilterFolded restricts to rows the summary projection HAS folded
	// (summary_folded=true) — the complement of FilterUnfolded. Used when a query
	// also evaluates the unfolded set live, so the SQL (folded) and live (unfolded)
	// result sets are provably disjoint and totals don't double-count.
	FilterFolded() MessageQuery
	// FilterEmailGroupIn restricts to rows whose email group — COALESCE(email_id, id)
	// — is in the given set. Used to compute the overlap between the folded (SQL) and
	// live (unfolded) result sets at the EMAIL-GROUP granularity: a copied message
	// mid-fold has one folded and one unfolded sibling sharing email_id, so the two
	// row-disjoint sets can still share a group; the total must dedup on the group.
	FilterEmailGroupIn(groupIDs []int64) MessageQuery
	// FilterSubject/FilterFrom/FilterTo are case-insensitive substring matches on
	// the denormalized summary columns (H13), so header searches run in SQL rather
	// than parsing every body.
	FilterSubject(substr string) MessageQuery
	FilterFrom(substr string) MessageQuery
	FilterTo(substr string) MessageQuery
	// FilterReceivedRange bounds received time; each RFC3339 bound is optional ("").
	FilterReceivedRange(after, before string) MessageQuery
	// FilterSizeRange bounds message size; each bound is optional (0 = unbounded).
	FilterSizeRange(min, max int64) MessageQuery
	// FilterKeyword matches messages that have (want=true) or lack (want=false) an
	// IMAP/JMAP keyword.
	FilterKeyword(kw string, want bool) MessageQuery
	SortUID() MessageQuery
	// SortReceivedDesc orders newest-first by received time (ties broken by id),
	// so list endpoints can page in SQL instead of loading + sorting in Go.
	SortReceivedDesc() MessageQuery
	// SortReceivedAsc orders oldest-first by received time (ties broken by id).
	SortReceivedAsc() MessageQuery
	// SortSizeDesc / SortSizeAsc order by message size (ties broken by id).
	SortSizeDesc() MessageQuery
	SortSizeAsc() MessageQuery
	// DistinctEmail collapses sibling rows of one JMAP Email (shared email_id) to a
	// single row, so LIMIT/OFFSET paging and Count over Emails are correct.
	DistinctEmail() MessageQuery
	Limit(n int) MessageQuery
	// Offset skips the first n rows (for LIMIT/OFFSET paging pushed into SQL).
	Offset(n int) MessageQuery

	ForEach(fn func(Message) error) error
	List() ([]Message, error)
	Count() (int, error)
}

// MailboxQuery covers LIST and mailbox lookups.
type MailboxQuery interface {
	FilterExpunged(bool) MailboxQuery
	ForEach(fn func(Mailbox) error) error
	List() ([]Mailbox, error)
}
