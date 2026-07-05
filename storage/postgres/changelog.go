package postgres

import (
	"encoding/json"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// Change-log entry kinds. Stable numeric codes persisted in changelog.kind.
// Each maps 1:1 to a store.Change variant.
const (
	kindAddUID uint8 = iota + 1
	kindRemoveUIDs
	kindFlags
	kindThread
	kindAddMailbox
	kindRemoveMailbox
	kindRenameMailbox
	kindAddSubscription
	kindRemoveSubscription
	kindMailboxCounts
	kindMailboxSpecialUse
	kindMailboxKeywords
	kindAnnotation
)

// encodeChange returns the kind code, the mailbox id for the per-mailbox replay
// index (0 if not applicable), and the JSON payload for a Change.
func encodeChange(c store.Change) (kind uint8, mailboxID int64, payload []byte, err error) {
	switch v := c.(type) {
	case store.ChangeAddUID:
		kind, mailboxID = kindAddUID, v.MailboxID
	case store.ChangeRemoveUIDs:
		kind, mailboxID = kindRemoveUIDs, v.MailboxID
	case store.ChangeFlags:
		kind, mailboxID = kindFlags, v.MailboxID
	case store.ChangeThread:
		kind = kindThread
	case store.ChangeAddMailbox:
		kind, mailboxID = kindAddMailbox, v.Mailbox.ID
	case store.ChangeRemoveMailbox:
		kind, mailboxID = kindRemoveMailbox, v.MailboxID
	case store.ChangeRenameMailbox:
		kind, mailboxID = kindRenameMailbox, v.MailboxID
	case store.ChangeAddSubscription:
		kind = kindAddSubscription
	case store.ChangeRemoveSubscription:
		kind = kindRemoveSubscription
	case store.ChangeMailboxCounts:
		kind, mailboxID = kindMailboxCounts, v.MailboxID
	case store.ChangeMailboxSpecialUse:
		kind, mailboxID = kindMailboxSpecialUse, v.MailboxID
	case store.ChangeMailboxKeywords:
		kind, mailboxID = kindMailboxKeywords, v.MailboxID
	case store.ChangeAnnotation:
		kind, mailboxID = kindAnnotation, v.MailboxID
	default:
		return 0, 0, nil, errUnknownChange
	}
	payload, err = json.Marshal(c)
	return kind, mailboxID, payload, err
}

// decodeChange reconstructs a store.Change from a persisted entry. It returns
// VALUE types (not pointers) so replayed changes are identical in dynamic type
// to the in-process ones the protocol code type-switches on.
func decodeChange(kind uint8, payload []byte) (store.Change, error) {
	switch kind {
	case kindAddUID:
		var v store.ChangeAddUID
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindRemoveUIDs:
		var v store.ChangeRemoveUIDs
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindFlags:
		var v store.ChangeFlags
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindThread:
		var v store.ChangeThread
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindAddMailbox:
		var v store.ChangeAddMailbox
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindRemoveMailbox:
		var v store.ChangeRemoveMailbox
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindRenameMailbox:
		var v store.ChangeRenameMailbox
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindAddSubscription:
		var v store.ChangeAddSubscription
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindRemoveSubscription:
		var v store.ChangeRemoveSubscription
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindMailboxCounts:
		var v store.ChangeMailboxCounts
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindMailboxSpecialUse:
		var v store.ChangeMailboxSpecialUse
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindMailboxKeywords:
		var v store.ChangeMailboxKeywords
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	case kindAnnotation:
		var v store.ChangeAnnotation
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, errUnknownChange
	}
}
