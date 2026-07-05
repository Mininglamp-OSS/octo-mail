package imapd

import (
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdIdle implements a minimal IMAP IDLE (RFC 2177). It registers a Comm on the
// selected account, replies "+ idling", and waits: on a change it pushes an
// untagged EXISTS with the new message count; on the client's "DONE" it returns.
// This is the cross-node payoff — a delivery on another node wakes this IDLE via
// the coordinator (Postgres LISTEN/NOTIFY → log replay → Comm).
func (c *conn) cmdIdle(tag string) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	comm := c.acc.RegisterComm()
	defer comm.Close()

	c.writef("+ idling")
	c.flush()

	// Read the client's DONE in a goroutine so we can select against changes.
	doneCh := make(chan struct{})
	go func() {
		for {
			line, err := c.readLine()
			if err != nil {
				close(doneCh)
				return
			}
			if strings.EqualFold(strings.TrimSpace(line), "DONE") {
				close(doneCh)
				return
			}
		}
	}()

	for {
		select {
		case <-doneCh:
			c.ok(tag, "IDLE terminated")
			return
		case changes, ok := <-comm.Changes:
			if !ok {
				c.ok(tag, "IDLE terminated")
				return
			}
			c.pushChanges(changes)
			c.flush()
		}
	}
}

// pushChanges emits untagged responses for a batch of changes relevant to the
// selected mailbox. For the compact core we surface new messages (EXISTS) and
// flag updates (FETCH FLAGS).
func (c *conn) pushChanges(changes []store.Change) {
	mbID := c.selected.ID
	newExists := false
	for _, ch := range changes {
		switch v := ch.(type) {
		case store.ChangeAddUID:
			if v.MailboxID == mbID {
				newExists = true
			}
		case store.ChangeFlags:
			if v.MailboxID == mbID {
				// A real server maps UID->seq; the compact core just signals a
				// flag change via an untagged FETCH by UID.
				c.writef(`* %d FETCH (UID %d FLAGS (%s))`, v.UID, v.UID, strings.Join(flagsToStrings(v.Flags, v.Keywords), " "))
			}
		}
	}
	if newExists {
		n := c.acc.MessageCount(c.ctx, mbID)
		c.writef("* %d EXISTS", n)
	}
}

func flagsToStrings(f store.Flags, kw []string) []string {
	return f.IMAPFlags(kw)
}
