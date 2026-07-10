package imapd

import (
	"fmt"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdGetQuota implements GETQUOTA and GETQUOTAROOT (RFC 9208 subset). octo-mail uses
// a single per-account quota root named "". Reports STORAGE in KiB (used, limit)
// when a limit is set. withRoot also emits the QUOTAROOT line for the mailbox.
func (c *conn) cmdGetQuota(tag, args string, withRoot bool) {
	if !c.requireAuth(tag) {
		return
	}
	used, _, limit, err := c.acc.QuotaUsage(c.ctx)
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	if withRoot {
		mbox := unquote(strings.TrimSpace(args))
		c.writef(`* QUOTAROOT %s ""`, quote(normalizeMailbox(mbox)))
	}
	if limit > 0 {
		// STORAGE resource is reported in 1024-byte units.
		c.writef(`* QUOTA "" (STORAGE %d %d)`, used/1024, limit/1024)
	} else {
		c.writef(`* QUOTA "" ()`)
	}
	c.ok(tag, "getquota completed")
}

// cmdNamespace implements NAMESPACE (RFC 2342). octo-mail uses a single personal
// namespace with "/" hierarchy and no shared/other-user namespaces.
func (c *conn) cmdNamespace(tag string) {
	if !c.requireAuth(tag) {
		return
	}
	// Personal namespace: prefix "" separator "/". No other/shared namespaces.
	c.writef(`* NAMESPACE (("" "/")) NIL NIL`)
	c.ok(tag, "NAMESPACE completed")
}

// cmdStatus implements STATUS (RFC 3501): report counts for a mailbox without
// selecting it. Supports MESSAGES, UIDNEXT, UIDVALIDITY, UNSEEN, HIGHESTMODSEQ.
func (c *conn) cmdStatus(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	mbName, itemsRaw := cut(strings.TrimSpace(args), " ")
	name := normalizeMailbox(unquote(mbName))
	itemsRaw = strings.TrimSpace(itemsRaw)
	itemsRaw = strings.TrimPrefix(itemsRaw, "(")
	itemsRaw = strings.TrimSuffix(itemsRaw, ")")
	items := strings.Fields(strings.ToUpper(itemsRaw))

	var mb *store.Mailbox
	var totalSize int64
	needSize := false
	for _, it := range items {
		if it == "SIZE" {
			needSize = true
		}
	}
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		m, err := c.acc.MailboxFind(tx, name)
		if err != nil {
			return err
		}
		if m == nil {
			return errNo("mailbox does not exist")
		}
		mb = m
		// DELETED comes from the maintained c_deleted counter (mb.Deleted); only
		// SIZE still needs a scan (no per-mailbox byte counter is summed per STATUS).
		if needSize {
			msgs, err := tx.QueryMessage().FilterMailbox(m.ID).List()
			if err != nil {
				return err
			}
			for _, msg := range msgs {
				totalSize += msg.Size
			}
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}

	var parts []string
	for _, it := range items {
		switch it {
		case "MESSAGES":
			parts = append(parts, fmt.Sprintf("MESSAGES %d", mb.Total))
		case "UIDNEXT":
			parts = append(parts, fmt.Sprintf("UIDNEXT %d", mb.UIDNext))
		case "UIDVALIDITY":
			parts = append(parts, fmt.Sprintf("UIDVALIDITY %d", mb.UIDValidity))
		case "UNSEEN":
			parts = append(parts, fmt.Sprintf("UNSEEN %d", mb.Unseen))
		case "HIGHESTMODSEQ":
			parts = append(parts, fmt.Sprintf("HIGHESTMODSEQ %d", mb.ModSeq))
		case "SIZE":
			parts = append(parts, fmt.Sprintf("SIZE %d", totalSize))
		case "DELETED":
			parts = append(parts, fmt.Sprintf("DELETED %d", mb.Deleted))
		case "MAILBOXID":
			parts = append(parts, fmt.Sprintf("MAILBOXID (%s)", mailboxObjectID(mb.ID)))
		case "RECENT":
			parts = append(parts, "RECENT 0")
		}
	}
	c.writef("* STATUS %s (%s)", quote(mb.Name), strings.Join(parts, " "))
	c.ok(tag, "STATUS completed")
}

// cmdClose implements CLOSE (expunge=true) and UNSELECT (expunge=false): leave
// the selected mailbox. CLOSE permanently removes \Deleted messages first.
func (c *conn) cmdClose(tag string, expunge bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	if expunge && !c.readOnly {
		// Expunge \Deleted messages silently (CLOSE emits no untagged EXPUNGE).
		err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
			msgs, err := tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
			if err != nil {
				return err
			}
			var del []store.Message
			for _, m := range msgs {
				if m.Deleted {
					del = append(del, m)
				}
			}
			if len(del) == 0 {
				return nil
			}
			_, _, err = c.acc.MessageRemove(tx, 0, c.selected, store.RemoveOpts{Expunge: true}, del...)
			return err
		})
		if err != nil {
			c.no(tag, err.Error())
			return
		}
	}
	c.selected = nil
	c.readOnly = false
	if expunge {
		c.ok(tag, "CLOSE completed")
	} else {
		c.ok(tag, "UNSELECT completed")
	}
}
