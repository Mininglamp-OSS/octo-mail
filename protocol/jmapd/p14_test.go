package jmapd_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestJMAPP14 proves the P1-4 additions over real HTTP: Identity/get returns the
// account's identity; Email/copy re-delivers a message into another mailbox;
// EmailSubmission/set validates identityId (a foreign identity is rejected, the
// account's own identity is accepted, enqueuing exactly one outbound message).
func TestJMAPP14(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, thread_refs, projection_cursor, queue RESTART IDENTITY CASCADE`); err != nil {
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

	// Deliver one message into the Inbox to copy/submit.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	raw := "Message-ID: <m@example.com>\r\nFrom: u1@example.com\r\nTo: dst@remote.example\r\nSubject: copyme\r\n\r\nbody\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	sub := &submit.Submitter{Pool: s.Pool, Blob: bs}
	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test", Submission: sub, Blob: bs}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	queueCount := func() int {
		var n int
		s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&n)
		return n
	}

	// --- P1-4a: Identity/get returns the account's single identity. ---
	ig := call(t, hs.URL, `["Identity/get", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	il := ig["list"].([]any)
	if len(il) != 1 {
		t.Fatalf("Identity/get returned %d identities, want 1", len(il))
	}
	ident := il[0].(map[string]any)
	wantIdentity := "I" + itoa(accID)
	if ident["id"] != wantIdentity {
		t.Fatalf("Identity id = %v, want %s", ident["id"], wantIdentity)
	}
	if ident["email"] != "u1@example.com" {
		t.Fatalf("Identity email = %v, want u1@example.com", ident["email"])
	}

	// --- P1-4b: Email/copy re-delivers the message into a new mailbox. ---
	cr := call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","create":{"m1":{"name":"Saved"}}}, "c2"]`)
	newMbID := cr["created"].(map[string]any)["m1"].(map[string]any)["id"].(string)
	cp := call(t, hs.URL, `["Email/copy", {"accountId":"`+itoa(accID)+`","create":{"cc":{"id":"E1","mailboxIds":{"`+newMbID+`":true}}}}, "c3"]`)
	cpCreated := cp["created"].(map[string]any)
	if cpCreated["cc"] == nil {
		t.Fatalf("Email/copy failed: %v", cp)
	}
	// The copy is a distinct Email in the new mailbox.
	newEmailID := cpCreated["cc"].(map[string]any)["id"].(string)
	if newEmailID == "E1" {
		t.Fatalf("Email/copy returned same id as source, want a new email")
	}
	// Source still exists.
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["E1"]}, "c4"]`)
	if len(g["list"].([]any)) != 1 {
		t.Fatalf("source email missing after copy")
	}

	// --- P1-4c: EmailSubmission/set validates identityId. ---
	// A foreign identity is rejected.
	bad := call(t, hs.URL, `["EmailSubmission/set", {"accountId":"`+itoa(accID)+`","create":{"s1":{"emailId":"E1","identityId":"I999","envelope":{"mailFrom":{"email":"u1@example.com"},"rcptTo":[{"email":"dst@remote.example"}]}}}}, "c5"]`)
	if bad["notCreated"].(map[string]any)["s1"] == nil {
		t.Fatalf("EmailSubmission with foreign identity should be rejected: %v", bad)
	}
	if queueCount() != 0 {
		t.Fatalf("foreign-identity submission was enqueued (n=%d), want 0", queueCount())
	}
	// The account's own identity is accepted.
	good := call(t, hs.URL, `["EmailSubmission/set", {"accountId":"`+itoa(accID)+`","create":{"s2":{"emailId":"E1","identityId":"`+wantIdentity+`","envelope":{"mailFrom":{"email":"u1@example.com"},"rcptTo":[{"email":"dst@remote.example"}]}}}}, "c6"]`)
	if good["created"].(map[string]any)["s2"] == nil {
		t.Fatalf("EmailSubmission with own identity should succeed: %v", good)
	}
	if queueCount() != 1 {
		t.Fatalf("own-identity submission not enqueued (n=%d), want 1", queueCount())
	}

	t.Logf("OK: Identity/get + Email/copy(new email, source intact) + EmailSubmission identity validation (foreign rejected, own accepted)")
}
