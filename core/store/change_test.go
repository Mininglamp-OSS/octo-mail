package store

import "testing"

// TestChangeModSeq verifies the Change variant set behaves as change-log entry
// kinds: modseq-bearing entries report their offset; derived entries report -1.
func TestChangeModSeq(t *testing.T) {
	cases := []struct {
		name string
		c    Change
		want ModSeq
	}{
		{"add-uid", ChangeAddUID{ModSeq: 42}, 42},
		{"remove-uids", ChangeRemoveUIDs{ModSeq: 43}, 43},
		{"flags", ChangeFlags{ModSeq: 44}, 44},
		{"add-mailbox", ChangeAddMailbox{Mailbox: Mailbox{ModSeq: 45}}, 45},
		{"rename-mailbox", ChangeRenameMailbox{ModSeq: 46}, 46},
		{"remove-mailbox", ChangeRemoveMailbox{ModSeq: 47}, 47},
		{"specialuse", ChangeMailboxSpecialUse{ModSeq: 48}, 48},
		{"annotation", ChangeAnnotation{ModSeq: 49}, 49},
		// Derived facts: no modseq.
		{"thread", ChangeThread{}, -1},
		{"add-sub", ChangeAddSubscription{}, -1},
		{"remove-sub", ChangeRemoveSubscription{}, -1},
		{"counts", ChangeMailboxCounts{}, -1},
		{"keywords", ChangeMailboxKeywords{}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.ChangeModSeq(); got != tc.want {
				t.Fatalf("ChangeModSeq() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestChangeSliceIsLoggable confirms all variants satisfy Change, i.e. the
// closed set can be persisted as a []Change log uniformly.
func TestChangeSliceIsLoggable(t *testing.T) {
	log := []Change{
		ChangeAddMailbox{Mailbox: Mailbox{ID: 1, Name: "Inbox", ModSeq: 1}},
		ChangeAddUID{MailboxID: 1, UID: 1, ModSeq: 2, Flags: Flags{Seen: false}},
		ChangeFlags{MailboxID: 1, UID: 1, ModSeq: 3, Mask: Flags{Seen: true}, Flags: Flags{Seen: true}},
		ChangeRemoveUIDs{MailboxID: 1, UIDs: []UID{1}, ModSeq: 4, MsgIDs: []int64{1}},
	}
	// The head of the log (max modseq that applies) must be 4 — the JMAP state /
	// IMAP HIGHESTMODSEQ for this account.
	var head ModSeq = -1
	for _, c := range log {
		if ms := c.ChangeModSeq(); ms > head {
			head = ms
		}
	}
	if head != 4 {
		t.Fatalf("log head modseq = %d, want 4", head)
	}
}

func TestCommRoundTrip(t *testing.T) {
	var closed bool
	c := NewComm(7, 1, func() { closed = true })
	if c.Account() != 7 {
		t.Fatalf("Account() = %d, want 7", c.Account())
	}
	c.Changes <- []Change{ChangeAddUID{ModSeq: 1}}
	got := <-c.Changes
	if len(got) != 1 || got[0].ChangeModSeq() != 1 {
		t.Fatalf("unexpected change delivered: %+v", got)
	}
	c.Close()
	if !closed {
		t.Fatalf("Close did not invoke unregister hook")
	}
}
