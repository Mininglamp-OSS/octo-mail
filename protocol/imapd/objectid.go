package imapd

import (
	"strconv"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// OBJECTID (RFC 8474) exposes stable, opaque identifiers for mailboxes, emails,
// and threads. octo-mail's change-log spine already assigns each of these a durable
// integer id, so the object ids are just those ids with a leading alphabetic
// prefix — the prefix both satisfies the RFC's "avoid all-digit / leading-digit"
// guidance and matches the M<id>/T<id> convention JMAP already uses, so the same
// identity is visible across both protocols.

func mailboxObjectID(id int64) string { return "B" + strconv.FormatInt(id, 10) }

// emailObjectID uses the message's effective email identity (the JMAP email id),
// so sibling rows of one email in multiple mailboxes report the same EMAILID.
func emailObjectID(m store.Message) string {
	return "M" + strconv.FormatInt(m.EffectiveEmailID(), 10)
}

// threadObjectID returns the THREADID, or "" when the message is not yet
// threaded (the async thread projection has not folded it); callers emit NIL.
func threadObjectID(m store.Message) string {
	if m.ThreadID == 0 {
		return ""
	}
	return "T" + strconv.FormatInt(m.ThreadID, 10)
}
