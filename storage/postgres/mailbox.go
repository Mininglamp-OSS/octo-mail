package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

const mailboxCols = `id, account_id, parent_id, name, uidvalidity, uidnext,
	createseq, modseq, expunged,
	su_archive, su_draft, su_junk, su_sent, su_trash, subscribed, keywords,
	c_total, c_deleted, c_unread, c_unseen, c_size`

func scanMailbox(row pgx.Row) (store.Mailbox, error) {
	var mb store.Mailbox
	var parent *int64
	err := row.Scan(&mb.ID, &mb.AccountID, &parent, &mb.Name, &mb.UIDValidity, &mb.UIDNext,
		&mb.CreateSeq, &mb.ModSeq, &mb.Expunged,
		&mb.Archive, &mb.Draft, &mb.Junk, &mb.Sent, &mb.Trash, &mb.Subscribed, &mb.Keywords,
		&mb.Total, &mb.Deleted, &mb.Unread, &mb.Unseen, &mb.Size)
	if err != nil {
		return store.Mailbox{}, err
	}
	if parent != nil {
		mb.ParentID = *parent
	}
	return mb, nil
}

// findMailbox looks up a non-expunged mailbox by name in the tx.
func (pt *pgTx) findMailbox(name string) (store.Mailbox, bool, error) {
	row := pt.tx.QueryRow(pt.ctx,
		`SELECT `+mailboxCols+` FROM mailboxes WHERE account_id=$1 AND name=$2 AND NOT expunged`,
		pt.acc.id, name)
	mb, err := scanMailbox(row)
	if err == pgx.ErrNoRows {
		return store.Mailbox{}, false, nil
	}
	if err != nil {
		return store.Mailbox{}, false, err
	}
	return mb, true, nil
}

// ensureMailbox finds or creates a mailbox, recording changes on creation.
func (pt *pgTx) ensureMailbox(name string, subscribe bool, su store.SpecialUse) (store.Mailbox, error) {
	if mb, ok, err := pt.findMailbox(name); err != nil || ok {
		return mb, err
	}
	uidvalidity, err := pt.nextUIDValidity()
	if err != nil {
		return store.Mailbox{}, err
	}
	seq := pt.nextModSeq()
	var id int64
	err = pt.tx.QueryRow(pt.ctx,
		`INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq,
			su_archive, su_draft, su_junk, su_sent, su_trash, subscribed)
		 VALUES ($1,$2,$3,1,$4,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		pt.acc.id, name, int64(uidvalidity), int64(seq),
		su.Archive, su.Draft, su.Junk, su.Sent, su.Trash, subscribe).Scan(&id)
	if err != nil {
		return store.Mailbox{}, err
	}
	mb := store.Mailbox{
		ID: id, AccountID: pt.acc.id, Name: name,
		UIDValidity: uidvalidity, UIDNext: 1, CreateSeq: seq, ModSeq: seq, SpecialUse: su,
	}
	if err := pt.record(store.ChangeAddMailbox{Mailbox: mb}); err != nil {
		return store.Mailbox{}, err
	}
	if subscribe {
		if err := pt.record(store.ChangeAddSubscription{MailboxName: name}); err != nil {
			return store.Mailbox{}, err
		}
	}
	return mb, nil
}

// --- kernel/store.Account mailbox methods (operate on the ambient tx) ---

func (a *account) MailboxFind(tx store.Tx, name string) (*store.Mailbox, error) {
	pt := tx.(*pgTx)
	mb, ok, err := pt.findMailbox(name)
	if err != nil || !ok {
		return nil, err
	}
	return &mb, nil
}

func (a *account) MailboxEnsure(tx store.Tx, name string, subscribe bool, su store.SpecialUse, modseq *store.ModSeq) (store.Mailbox, []store.Change, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)
	mb, err := pt.ensureMailbox(name, subscribe, su)
	if err != nil {
		return store.Mailbox{}, nil, err
	}
	return mb, pt.changes[before:], nil
}

func (a *account) MailboxCreate(tx store.Tx, name string, su store.SpecialUse) (store.Mailbox, []store.Change, []string, bool, error) {
	pt := tx.(*pgTx)
	if _, ok, err := pt.findMailbox(name); err != nil {
		return store.Mailbox{}, nil, nil, false, err
	} else if ok {
		return store.Mailbox{}, nil, nil, true, nil
	}
	before := len(pt.changes)
	// IMAP CREATE does not subscribe the mailbox (RFC 3501 — subscription is a
	// separate SUBSCRIBE step). DeliverMailbox subscribes auto-created mailboxes
	// via MailboxEnsure(subscribe=true) on its own.
	mb, err := pt.ensureMailbox(name, false, su)
	if err != nil {
		return store.Mailbox{}, nil, nil, false, err
	}
	return mb, pt.changes[before:], []string{name}, false, nil
}

func (a *account) MailboxRename(tx store.Tx, src *store.Mailbox, dst string, modseq *store.ModSeq) ([]store.Change, bool, bool, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)
	seq := pt.nextModSeq()
	ct, err := pt.tx.Exec(pt.ctx,
		`UPDATE mailboxes SET name=$1, modseq=$2 WHERE id=$3 AND account_id=$4 AND NOT expunged`,
		dst, int64(seq), src.ID, pt.acc.id)
	if err != nil {
		return nil, false, false, err
	}
	if ct.RowsAffected() == 0 {
		return nil, false, true, nil
	}
	if err := pt.record(store.ChangeRenameMailbox{MailboxID: src.ID, OldName: src.Name, NewName: dst, ModSeq: seq}); err != nil {
		return nil, false, false, err
	}
	return pt.changes[before:], false, false, nil
}

func (a *account) MailboxDelete(ctx context.Context, tx store.Tx, mb *store.Mailbox) ([]store.Change, bool, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)
	seq := pt.nextModSeq()
	if _, err := pt.tx.Exec(pt.ctx,
		`UPDATE mailboxes SET expunged=true, modseq=$1 WHERE id=$2 AND account_id=$3`,
		int64(seq), mb.ID, pt.acc.id); err != nil {
		return nil, false, err
	}
	if err := pt.record(store.ChangeRemoveMailbox{MailboxID: mb.ID, Name: mb.Name, ModSeq: seq}); err != nil {
		return nil, false, err
	}
	return pt.changes[before:], false, nil
}

func (a *account) SubscriptionEnsure(tx store.Tx, name string) ([]store.Change, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)
	if _, err := pt.tx.Exec(pt.ctx,
		`UPDATE mailboxes SET subscribed=true WHERE account_id=$1 AND name=$2 AND NOT expunged`,
		pt.acc.id, name); err != nil {
		return nil, err
	}
	if err := pt.record(store.ChangeAddSubscription{MailboxName: name}); err != nil {
		return nil, err
	}
	return pt.changes[before:], nil
}

// SubscriptionRemove clears the subscribed flag (IMAP UNSUBSCRIBE) and records
// the change on the log.
func (a *account) SubscriptionRemove(tx store.Tx, name string) ([]store.Change, error) {
	pt := tx.(*pgTx)
	before := len(pt.changes)
	if _, err := pt.tx.Exec(pt.ctx,
		`UPDATE mailboxes SET subscribed=false WHERE account_id=$1 AND name=$2 AND NOT expunged`,
		pt.acc.id, name); err != nil {
		return nil, err
	}
	if err := pt.record(store.ChangeRemoveSubscription{MailboxName: name}); err != nil {
		return nil, err
	}
	return pt.changes[before:], nil
}
