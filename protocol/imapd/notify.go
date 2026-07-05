package imapd

import (
	"context"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdNotify implements a compact IMAP NOTIFY (RFC 5465). The full grammar is
// large; this supports the common client usage:
//
//	NOTIFY SET [STATUS] (selected (MessageNew MessageExpunge FlagChange)) ...
//	NOTIFY NONE
//
// While NOTIFY is SET, a background pusher registers on the account's Comm and
// emits unsolicited EXISTS / FETCH responses for the selected mailbox — even
// while the client runs other commands (unlike IDLE, which blocks). Writes are
// serialized with the command loop via c.wmu so responses never interleave.
func (c *conn) cmdNotify(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)
	word, _ := cut(rest, " ")
	switch strings.ToUpper(word) {
	case "NONE":
		c.stopNotify()
		c.ok(tag, "NOTIFY completed")
	case "SET":
		// Restart any existing pusher with the new registration. We watch the
		// selected mailbox (the widely-used case); the event list is accepted and
		// we surface MessageNew (EXISTS) and FlagChange (FETCH).
		c.stopNotify()
		if c.selected == nil {
			c.no(tag, "NOTIFY SET requires a selected mailbox in this implementation")
			return
		}
		c.startNotify()
		c.ok(tag, "NOTIFY completed")
	default:
		c.no(tag, "NOTIFY expects SET or NONE")
	}
}

// startNotify launches the background Comm pusher for the selected mailbox.
func (c *conn) startNotify() {
	comm := c.acc.RegisterComm()
	ctx, cancel := context.WithCancel(c.ctx)
	c.notifyStop = func() {
		cancel()
		comm.Close()
	}
	mbID := c.selected.ID
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case changes, ok := <-comm.Changes:
				if !ok {
					return
				}
				c.pushNotify(mbID, changes)
				c.flush()
			}
		}
	}()
}

// stopNotify cancels the active pusher, if any.
func (c *conn) stopNotify() {
	if c.notifyStop != nil {
		c.notifyStop()
		c.notifyStop = nil
	}
}

// pushNotify emits unsolicited responses for changes to the watched mailbox.
// Mirrors pushChanges but scoped to a fixed mailbox id captured at NOTIFY SET.
func (c *conn) pushNotify(mbID int64, changes []store.Change) {
	newExists := false
	for _, ch := range changes {
		switch v := ch.(type) {
		case store.ChangeAddUID:
			if v.MailboxID == mbID {
				newExists = true
			}
		case store.ChangeFlags:
			if v.MailboxID == mbID {
				c.writef(`* %d FETCH (UID %d FLAGS (%s))`, v.UID, v.UID, strings.Join(flagsToStrings(v.Flags, v.Keywords), " "))
			}
		case store.ChangeRemoveUIDs:
			if v.MailboxID == mbID {
				for _, uid := range v.UIDs {
					c.writef("* VANISHED %d", uid)
				}
			}
		}
	}
	if newExists {
		n := c.acc.MessageCount(c.ctx, mbID)
		c.writef("* %d EXISTS", n)
	}
}
