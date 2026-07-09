// Package store defines the kernel storage interfaces and the shared "shape"
// types that the reused protocol servers (imapserver/smtpserver/jmapserver)
// bind to.
//
// Design: the change-log is the spine. Every mutation appends immutable,
// per-account, monotonically-sequenced Change entries; mailbox/message state is
// a materialized projection of that log. The shape types below (Flags, UID,
// ModSeq, the Change* variants, Comm) are lifted verbatim from the store
// package so ~20K LOC of protocol code compiles unchanged; only the backing
// implementation (Postgres + S3, see storage/postgres) differs.
//
// A per-account monotonic counter (the changelog seq) simultaneously serves IMAP
// MODSEQ/CONDSTORE and JMAP state — they are two views of one log offset.
package store

import "time"

// UID is an IMAP message UID, unique and monotonic within a mailbox.
type UID uint32

// ModSeq is a per-account modification sequence. It equals the account's
// change-log offset: IMAP HIGHESTMODSEQ and JMAP state are both max(seq).
type ModSeq int64

// Flags are the system flags of a message. A flag change is a single change-log
// entry (ChangeFlags) plus one projection row update.
type Flags struct {
	Seen      bool
	Answered  bool
	Flagged   bool
	Forwarded bool
	Junk      bool
	Notjunk   bool
	Deleted   bool
	Draft     bool
	Phishing  bool
	MDNSent   bool
}

// SpecialUse marks a mailbox's role, understood by mail clients.
type SpecialUse struct {
	Archive bool
	Draft   bool
	Junk    bool
	Sent    bool
	Trash   bool
}

// MailboxCounts are per-mailbox statistics, kept current as a projection.
type MailboxCounts struct {
	Total   int64
	Deleted int64
	Unread  int64
	Unseen  int64
	Size    int64
}

// Mailbox is a projection row: a folder in an account, derived from the log.
type Mailbox struct {
	ID          int64
	AccountID   int64
	ParentID    int64
	Name        string // Slash-separated hierarchy; "Inbox" is special.
	UIDValidity uint32
	UIDNext     UID
	CreateSeq   ModSeq
	ModSeq      ModSeq
	Expunged    bool
	SpecialUse
	Subscribed bool     // IMAP SUBSCRIBE state (LIST-EXTENDED \Subscribed).
	Keywords   []string // Lower-cased, sorted, per-mailbox keyword set.
	MailboxCounts
}

// Message is a projection row: message metadata. The body lives in the blob
// store, referenced by BlobRef; MsgPrefix holds generated headers (Received,
// Authentication-Results) prepended on read.
type Message struct {
	ID        int64
	AccountID int64
	MailboxID int64
	UID       UID
	CreateSeq ModSeq
	ModSeq    ModSeq
	Expunged  bool

	Flags
	Keywords []string

	BlobRef  string // Content-hash reference into the blob store.
	Size     int64
	ThreadID int64

	// EmailID groups sibling rows that are the same message present in multiple
	// mailboxes (the JMAP multi-mailbox model). Zero means the row is its own
	// email; EffectiveEmailID then returns the row's own ID. IMAP is unaffected —
	// each row is still an independent (mailbox, uid) with its own flags.
	EmailID int64

	Received time.Time // When the message was received/appended (IMAP INTERNALDATE).
	SaveDate time.Time // When this row entered its mailbox (IMAP SAVEDATE, RFC 8514).

	MsgPrefix []byte // Generated headers, prepended to the blob on read.

	// Denormalized list-summary fields (H13), populated by the threading
	// projection fold so list/query paths need not MIME-parse the body per row.
	// SummaryFolded is false until the fold has run for this row; list endpoints
	// fall back to an on-the-fly parse while false (see summarize).
	Subject       string
	FromAddr      string
	ToAddrs       string // space-joined recipient addresses
	Preview       string
	SummaryFolded bool
}

// EffectiveEmailID returns the message's JMAP email identity: its EmailID group
// if set, otherwise its own row ID (a plain, un-copied message is its own email).
func (m Message) EffectiveEmailID() int64 {
	if m.EmailID != 0 {
		return m.EmailID
	}
	return m.ID
}

// flagSpec is one row of the canonical flag registry: the pointer into a Flags
// value, its IMAP token (\Seen, $Junk, ...) and its JMAP keyword ($seen, ...).
// This single table is the source of truth for every flag<->wire conversion, so
// the IMAP, JMAP and WebAPI surfaces cannot drift apart (e.g. one emitting Junk
// while another omits it).
type flagSpec struct {
	ptr  func(*Flags) *bool
	imap string // IMAP system flag / keyword token
	jmap string // JMAP keyword
}

var flagRegistry = []flagSpec{
	{func(f *Flags) *bool { return &f.Seen }, `\Seen`, "$seen"},
	{func(f *Flags) *bool { return &f.Answered }, `\Answered`, "$answered"},
	{func(f *Flags) *bool { return &f.Flagged }, `\Flagged`, "$flagged"},
	{func(f *Flags) *bool { return &f.Deleted }, `\Deleted`, "$deleted"},
	{func(f *Flags) *bool { return &f.Draft }, `\Draft`, "$draft"},
	{func(f *Flags) *bool { return &f.Forwarded }, `$Forwarded`, "$forwarded"},
	{func(f *Flags) *bool { return &f.Junk }, `$Junk`, "$junk"},
	{func(f *Flags) *bool { return &f.Notjunk }, `$NotJunk`, "$notjunk"},
	{func(f *Flags) *bool { return &f.Phishing }, `$Phishing`, "$phishing"},
	{func(f *Flags) *bool { return &f.MDNSent }, `$MDNSent`, "$mdnsent"},
}

// IMAPFlags renders the set flags as IMAP tokens (\Seen, $Junk, ...), followed
// by the given per-message keywords. It is the one renderer the IMAP FETCH/STORE
// and WebAPI surfaces share.
func (f Flags) IMAPFlags(keywords []string) []string {
	fc := f
	var out []string
	for _, s := range flagRegistry {
		if *s.ptr(&fc) {
			out = append(out, s.imap)
		}
	}
	return append(out, keywords...)
}

// JMAPKeywords renders the set flags plus per-message keywords as a JMAP keyword
// map ($seen, $flagged, ...). Returns nil when empty (JMAP omits empty maps).
func (f Flags) JMAPKeywords(keywords []string) map[string]bool {
	fc := f
	kw := map[string]bool{}
	for _, s := range flagRegistry {
		if *s.ptr(&fc) {
			kw[s.jmap] = true
		}
	}
	for _, k := range keywords {
		kw[k] = true
	}
	if len(kw) == 0 {
		return nil
	}
	return kw
}

// SetByName sets a single flag by an IMAP token or JMAP keyword (case- and
// prefix-insensitive: "\Seen", "$seen" and "seen" all map to Seen). It reports
// whether name matched a known system flag; when false, the caller should treat
// name as a free-form keyword. This is the one parser all surfaces share, so a
// token handled by one protocol is handled identically by the others.
func (f *Flags) SetByName(name string, v bool) (known bool) {
	n := normalizeFlagName(name)
	for _, s := range flagRegistry {
		if normalizeFlagName(s.imap) == n || normalizeFlagName(s.jmap) == n {
			*s.ptr(f) = v
			return true
		}
	}
	return false
}

// normalizeFlagName lowercases and strips a leading \ or $ so IMAP and JMAP
// spellings of the same flag compare equal.
func normalizeFlagName(name string) string {
	n := ""
	for _, r := range name {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		n += string(r)
	}
	for len(n) > 0 && (n[0] == '\\' || n[0] == '$') {
		n = n[1:]
	}
	return n
}

// Annotation is an IMAP METADATA (RFC 5464) entry: a per-mailbox or server-level
// (MailboxID=0) key/value. Value is nil when the entry is absent.
type Annotation struct {
	MailboxID int64
	Key       string
	Value     []byte
	IsString  bool
}

// VacationResponse is the JMAP (RFC 8621 §8) auto-reply configuration for an
// account. Times are optional bounds; zero means unbounded.
type VacationResponse struct {
	Enabled  bool
	Subject  string
	TextBody string
	HTMLBody string
	FromDate time.Time
	ToDate   time.Time
}
