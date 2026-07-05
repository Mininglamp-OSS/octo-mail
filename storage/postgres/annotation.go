package postgres

import (
	"context"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// AnnotationSet stores or removes an IMAP METADATA entry and records a
// ChangeAnnotation on the account log. A nil value removes the entry.
func (a *account) AnnotationSet(ctx context.Context, mailboxID int64, key string, value []byte, isString bool) error {
	return a.Tx(ctx, func(tx store.Tx) error {
		pt := tx.(*pgTx)
		if value == nil {
			if _, err := pt.tx.Exec(pt.ctx,
				`DELETE FROM annotations WHERE account_id=$1 AND mailbox_id=$2 AND key=$3`,
				a.id, mailboxID, key); err != nil {
				return err
			}
		} else {
			if _, err := pt.tx.Exec(pt.ctx,
				`INSERT INTO annotations (account_id, mailbox_id, key, value, is_string)
				 VALUES ($1,$2,$3,$4,$5)
				 ON CONFLICT (account_id, mailbox_id, key)
				 DO UPDATE SET value=EXCLUDED.value, is_string=EXCLUDED.is_string`,
				a.id, mailboxID, key, value, isString); err != nil {
				return err
			}
		}
		modseq := pt.nextModSeq()
		var mbName string
		if mailboxID != 0 {
			_ = pt.tx.QueryRow(pt.ctx, `SELECT name FROM mailboxes WHERE account_id=$1 AND id=$2`, a.id, mailboxID).Scan(&mbName)
		}
		return pt.record(store.ChangeAnnotation{
			MailboxID: mailboxID, MailboxName: mbName, Key: key, ModSeq: modseq,
		})
	})
}

// AnnotationList returns a mailbox's annotations whose key is at or below one of
// the prefixes (empty prefixes = all entries).
func (a *account) AnnotationList(ctx context.Context, mailboxID int64, prefixes []string) ([]store.Annotation, error) {
	rows, err := a.s.Pool.Query(ctx,
		`SELECT mailbox_id, key, value, is_string FROM annotations
		 WHERE account_id=$1 AND mailbox_id=$2 ORDER BY key`,
		a.id, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Annotation
	for rows.Next() {
		var an store.Annotation
		if err := rows.Scan(&an.MailboxID, &an.Key, &an.Value, &an.IsString); err != nil {
			return nil, err
		}
		if len(prefixes) > 0 && !keyMatchesAny(an.Key, prefixes) {
			continue
		}
		out = append(out, an)
	}
	return out, rows.Err()
}

// keyMatchesAny reports whether key equals or is a child (prefix + "/") of any
// entry — RFC 5464 GETMETADATA returns the named entry and everything below it.
func keyMatchesAny(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if key == p || strings.HasPrefix(key, p+"/") {
			return true
		}
	}
	return false
}
