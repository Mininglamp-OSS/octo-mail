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
// The method set is exactly what the reused protocol handlers call. WithWLock
// serializes writers for the account; on the Postgres backend it acquires a
// transaction-scoped advisory lock so serialization holds across stateless nodes.
type Account interface {
	ID() int64

	// WithWLock/WithRLock run fn under the account's write/read lock.
	WithWLock(fn func())
	WithRLock(fn func())

	// Tx runs fn in a database transaction (read-write). The advisory writer
	// lock is taken inside write transactions.
	Tx(ctx context.Context, fn func(Tx) error) error

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
	DeliverMailbox(mailbox string, m *Message, body BlobReader) ([]Change, error)
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
	MessageReader(m Message) BlobReader

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
	SortUID() MessageQuery
	Limit(n int) MessageQuery

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
