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

// TestJMAPSubmissionSenderOwnership proves the H1 JMAP leg (PR #26 review): an
// EmailSubmission/set whose envelope mailFrom is NOT an address of the
// authenticated account is rejected with forbiddenFrom and enqueues nothing —
// symmetric with the SMTP submission ownership test.
func TestJMAPSubmissionSenderOwnership(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
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

	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	raw := "Message-ID: <m1@example.com>\r\nSubject: hi\r\nFrom: u1@example.com\r\nTo: bob@remote.example\r\n\r\nbody\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test", Blob: bs, Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 1 {
		t.Fatalf("Email/query returned %d ids, want 1", len(ids))
	}
	emailID := ids[0]

	// Foreign mailFrom (not an address of the authenticated account) → rejected.
	body := `["EmailSubmission/set", {"accountId":"` + itoa(accID) + `","create":{"spoof":{` +
		`"emailId":"` + emailID + `",` +
		`"envelope":{"mailFrom":{"email":"ceo@victim.example"},"rcptTo":[{"email":"bob@remote.example"}]}}}}, "c2"]`
	res := call(t, hs.URL, body)

	if created, _ := res["created"].(map[string]any); created != nil && created["spoof"] != nil {
		t.Fatalf("H1(JMAP) LEAK: foreign mailFrom was accepted: %v", created["spoof"])
	}
	notCreated, _ := res["notCreated"].(map[string]any)
	if notCreated == nil || notCreated["spoof"] == nil {
		t.Fatalf("expected 'spoof' in notCreated, got: %v", res)
	}
	sp, _ := notCreated["spoof"].(map[string]any)
	if sp["type"] != "forbiddenFrom" {
		t.Fatalf("rejection type = %v, want forbiddenFrom", sp["type"])
	}
	var qn int
	sc(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 0 {
		t.Fatalf("spoofed submission enqueued %d rows, want 0", qn)
	}

	// Control: the account's own address is accepted and enqueues.
	ok := call(t, hs.URL, `["EmailSubmission/set", {"accountId":"`+itoa(accID)+`","create":{"good":{`+
		`"emailId":"`+emailID+`",`+
		`"envelope":{"mailFrom":{"email":"u1@example.com"},"rcptTo":[{"email":"bob@remote.example"}]}}}}, "c3"]`)
	if created, _ := ok["created"].(map[string]any); created == nil || created["good"] == nil {
		t.Fatalf("own-address submission should succeed, got: %v", ok)
	}

	t.Logf("OK: JMAP EmailSubmission foreign mailFrom → forbiddenFrom (0 queued); own address → accepted")
}
