package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// TestFlagUpdateAdjustsCounts proves the H4 fix (#6): marking a message \Seen via
// tx.Update decrements the mailbox unseen/unread counters, and clearing it
// increments them again. Before the fix, Update recorded the flag change but
// never touched the counts, so IMAP STATUS(UNSEEN)/JMAP unreadEmails drifted on
// the commonest operation.
func TestFlagUpdateAdjustsCounts(t *testing.T) {
	ctx := context.Background()
	s, dir, accID := setupTest(t)

	target, err := resolveInbound(t, dir, "u1@example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	m := &store.Message{}
	if _, err := target.Deliver(ctx, m, memReader("From: a@remote.example\r\nTo: u1@example.com\r\nSubject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	unseen := func() int {
		var n int
		must(t, s.Pool.QueryRow(ctx,
			`SELECT c_unseen FROM mailboxes WHERE id=$1`, m.MailboxID).Scan(&n))
		return n
	}
	unread := func() int {
		var n int
		must(t, s.Pool.QueryRow(ctx,
			`SELECT c_unread FROM mailboxes WHERE id=$1`, m.MailboxID).Scan(&n))
		return n
	}

	if unseen() != 1 || unread() != 1 {
		t.Fatalf("after delivery: unseen=%d unread=%d, want 1/1", unseen(), unread())
	}

	// Mark \Seen → both counters drop to 0.
	acc, _, _, err := s.LookupAccountByID(ctx, accID)
	if err != nil {
		t.Fatal(err)
	}
	set := func(seen bool) {
		e := acc.Tx(ctx, func(tx store.Tx) error {
			var mm store.Message
			mm.ID = m.ID
			if err := tx.Get(&mm); err != nil {
				return err
			}
			mm.Seen = seen
			return tx.Update(&mm)
		})
		if e != nil {
			t.Fatalf("set seen=%v: %v", seen, e)
		}
	}

	set(true)
	if unseen() != 0 || unread() != 0 {
		t.Fatalf("after \\Seen: unseen=%d unread=%d, want 0/0", unseen(), unread())
	}
	// Idempotent: marking \Seen again must not underflow.
	set(true)
	if unseen() != 0 {
		t.Fatalf("re-\\Seen underflowed: unseen=%d, want 0", unseen())
	}
	// Clear \Seen → back to 1.
	set(false)
	if unseen() != 1 || unread() != 1 {
		t.Fatalf("after clear \\Seen: unseen=%d unread=%d, want 1/1", unseen(), unread())
	}
	t.Logf("OK: flag update keeps c_unseen/c_unread in step (1→0→0→1)")
}
