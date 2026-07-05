package store

// Change is one entry in an account's append-only change-log — the durable,
// ordered source of truth. Mailbox/message state is a fold of these. Each
// variant maps 1:1 to a log entry kind. ChangeModSeq returns the entry's
// account log offset, or -1 when the change carries no modseq (e.g. thread
// mute, subscription, mailbox counts — derived facts that don't advance IMAP
// MODSEQ but are still logged).
//
// Lifted from the store change model so protocol code that produces/consumes
// []Change compiles unchanged; here the slice is persisted, not just broadcast.
type Change interface {
	ChangeModSeq() ModSeq
}

// ChangeAddUID: a new message appeared in a mailbox.
type ChangeAddUID struct {
	MailboxID        int64
	UID              UID
	ModSeq           ModSeq
	Flags            Flags
	Keywords         []string
	MessageCountIMAP uint32
	Unseen           uint32
}

func (c ChangeAddUID) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeRemoveUIDs: one or more messages were expunged from a mailbox.
type ChangeRemoveUIDs struct {
	MailboxID        int64
	UIDs             []UID // Increasing UID order, for IMAP.
	ModSeq           ModSeq
	MsgIDs           []int64
	UIDNext          UID
	MessageCountIMAP uint32
	Unseen           uint32
}

func (c ChangeRemoveUIDs) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeFlags: system flags/keywords of a message changed.
type ChangeFlags struct {
	MailboxID   int64
	UID         UID
	ModSeq      ModSeq
	Mask        Flags // Which flags are modified.
	Flags       Flags // New values (all, not just mask).
	Keywords    []string
	UIDValidity uint32
	Unseen      uint32
}

func (c ChangeFlags) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeThread: thread mute/collapse changed.
type ChangeThread struct {
	MessageIDs []int64
	Muted      bool
	Collapsed  bool
}

func (c ChangeThread) ChangeModSeq() ModSeq { return -1 }

// ChangeRemoveMailbox: a mailbox was removed.
type ChangeRemoveMailbox struct {
	MailboxID int64
	Name      string
	ModSeq    ModSeq
}

func (c ChangeRemoveMailbox) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeAddMailbox: a mailbox was created.
type ChangeAddMailbox struct {
	Mailbox
	Flags []string // e.g. \Subscribed.
}

func (c ChangeAddMailbox) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeRenameMailbox: a mailbox was renamed.
type ChangeRenameMailbox struct {
	MailboxID int64
	OldName   string
	NewName   string
	Flags     []string
	ModSeq    ModSeq
}

func (c ChangeRenameMailbox) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeAddSubscription: a mailbox subscription was added.
type ChangeAddSubscription struct {
	MailboxName string
	ListFlags   []string
}

func (c ChangeAddSubscription) ChangeModSeq() ModSeq { return -1 }

// ChangeRemoveSubscription: a mailbox subscription was removed.
type ChangeRemoveSubscription struct {
	MailboxName string
	ListFlags   []string
}

func (c ChangeRemoveSubscription) ChangeModSeq() ModSeq { return -1 }

// ChangeMailboxCounts: total/deleted/unseen/unread changed.
type ChangeMailboxCounts struct {
	MailboxID   int64
	MailboxName string
	MailboxCounts
}

func (c ChangeMailboxCounts) ChangeModSeq() ModSeq { return -1 }

// ChangeMailboxSpecialUse: a special-use flag changed.
type ChangeMailboxSpecialUse struct {
	MailboxID   int64
	MailboxName string
	SpecialUse  SpecialUse
	ModSeq      ModSeq
}

func (c ChangeMailboxSpecialUse) ChangeModSeq() ModSeq { return c.ModSeq }

// ChangeMailboxKeywords: the mailbox's keyword set changed.
type ChangeMailboxKeywords struct {
	MailboxID   int64
	MailboxName string
	Keywords    []string
}

func (c ChangeMailboxKeywords) ChangeModSeq() ModSeq { return -1 }

// ChangeAnnotation: a mailbox or per-account annotation changed.
type ChangeAnnotation struct {
	MailboxID   int64
	MailboxName string
	Key         string
	ModSeq      ModSeq
}

func (c ChangeAnnotation) ChangeModSeq() ModSeq { return c.ModSeq }
