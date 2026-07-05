package jmapd_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestMultiMailboxPerEmail proves the JMAP multi-mailbox model: ONE Email whose
// mailboxIds is a set. Adding a mailboxId via Email/set materializes a sibling
// row (IMAP sees a second message in the second folder) while Email/get still
// returns a single Email with both mailboxIds and shared keywords. A flag set
// fans out to every row of the group; removing a mailboxId expunges that folder's
// row. Verified over real HTTP + direct DB assertions for the IMAP-row invariant.
func TestMultiMailboxPerEmail(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, thread_refs, projection_cursor RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Deliver one message into the Inbox (Email E1, one row).
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	raw := "Message-ID: <m@example.com>\r\nFrom: alice@remote.example\r\nTo: u1@example.com\r\nSubject: shared\r\n\r\nbody\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Identify the Inbox mailbox id and create a second mailbox "Archive".
	var inboxID int64
	sc(t, s, ctx, `SELECT id FROM mailboxes WHERE account_id=$1 AND name='Inbox'`, &inboxID, accID)
	cr := call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","create":{"a":{"name":"Archive"}}}, "c1"]`)
	archiveID := cr["created"].(map[string]any)["a"].(map[string]any)["id"].(string)

	countRows := func() int {
		var n int
		s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, accID).Scan(&n)
		return n
	}

	// Baseline: one row, Email E1 present only in Inbox.
	if countRows() != 1 {
		t.Fatalf("baseline rows = %d, want 1", countRows())
	}

	// --- Add Archive to E1's mailboxIds via patch: ONE email, now TWO mailboxes. ---
	up := call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"E1":{"mailboxIds/`+archiveID+`":true}}}, "c2"]`)
	if up["updated"].(map[string]any)["E1"] == nil {
		if nu, ok := up["notUpdated"].(map[string]any); ok && nu["E1"] != nil {
			t.Fatalf("Email/set add mailboxId failed: %v", nu["E1"])
		}
	}
	// IMAP-level invariant: there are now TWO rows (one per mailbox), independent uids.
	if countRows() != 2 {
		t.Fatalf("after adding mailboxId, rows = %d, want 2 (one per mailbox)", countRows())
	}
	// JMAP-level: still ONE Email E1, with BOTH mailboxIds.
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["E1"]}, "c3"]`)
	glist := g["list"].([]any)
	if len(glist) != 1 {
		t.Fatalf("Email/get returned %d emails, want 1 (multi-mailbox is one Email)", len(glist))
	}
	em := glist[0].(map[string]any)
	mids := em["mailboxIds"].(map[string]any)
	if len(mids) != 2 || !mids[itoa(inboxID)].(bool) || !mids[archiveID].(bool) {
		t.Fatalf("mailboxIds = %v, want {Inbox, Archive}", mids)
	}
	// Email/query in Archive returns the SAME email id E1 (not a new one).
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"inMailbox":"`+archiveID+`"}}, "c4"]`)
	qids := toStrings(q["ids"])
	if len(qids) != 1 || qids[0] != "E1" {
		t.Fatalf("Email/query in Archive = %v, want [E1]", qids)
	}

	// --- Flag fan-out: set $seen on E1 → BOTH rows become seen. ---
	call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"E1":{"keywords/$seen":true}}}, "c5"]`)
	var seenCount int
	sc(t, s, ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged AND f_seen`, &seenCount, accID)
	if seenCount != 2 {
		t.Fatalf("after keywords/$seen, seen rows = %d, want 2 (fan-out to all group rows)", seenCount)
	}

	// --- Remove Inbox from mailboxIds: E1 now lives only in Archive. ---
	call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"E1":{"mailboxIds/`+itoa(inboxID)+`":false}}}, "c6"]`)
	if countRows() != 1 {
		t.Fatalf("after removing Inbox, rows = %d, want 1", countRows())
	}
	g2 := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["E1"]}, "c7"]`)
	em2 := g2["list"].([]any)[0].(map[string]any)
	mids2 := em2["mailboxIds"].(map[string]any)
	if len(mids2) != 1 || !mids2[archiveID].(bool) {
		t.Fatalf("mailboxIds after remove = %v, want {Archive} only", mids2)
	}
	// The Inbox row is gone at the IMAP level.
	var inboxRows int
	sc(t, s, ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND mailbox_id=$2 AND NOT expunged`, &inboxRows, accID, inboxID)
	if inboxRows != 0 {
		t.Fatalf("Inbox rows after remove = %d, want 0", inboxRows)
	}

	t.Logf("OK: one Email E1 across Inbox+Archive (2 IMAP rows, 1 JMAP Email); $seen fanned to both; removing a mailboxId expunged that folder's row")
}
