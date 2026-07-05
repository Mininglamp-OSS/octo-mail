package jmapd_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestJMAPSubmissionAndThreadId proves two WF4 JMAP additions end to end over
// HTTP:
//  1. EmailSubmission/set enqueues an existing Email to the SAME shared outbound
//     queue that SMTP submission (587) feeds — send is protocol-agnostic.
//  2. Email/get exposes threadId once the async threading projection has folded,
//     so JMAP and IMAP share one conversation identity.
func TestJMAPSubmissionAndThreadId(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log, thread_refs, projection_cursor RESTART IDENTITY CASCADE`); err != nil {
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

	// Deliver a message with a Message-ID (so threading has something to fold).
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	raw := "Message-ID: <m1@example.com>\r\nSubject: hi\r\nFrom: u1@example.com\r\nTo: bob@remote.example\r\n\r\nsend me out\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{
		Dir:        dir,
		BaseURL:    "http://jmap.test",
		Submission: &submit.Submitter{Pool: s.Pool, Blob: bs},
	}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Find the Email id via Email/query.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 1 {
		t.Fatalf("Email/query returned %d ids, want 1", len(ids))
	}
	emailID := ids[0]

	// 1. EmailSubmission/set: enqueue to the shared outbound queue.
	body := `["EmailSubmission/set", {"accountId":"` + itoa(accID) + `","create":{"sub1":{` +
		`"emailId":"` + emailID + `",` +
		`"envelope":{"mailFrom":{"email":"u1@example.com"},"rcptTo":[{"email":"bob@remote.example"}]}}}}, "c2"]`
	res := call(t, hs.URL, body)
	createdRaw, ok := res["created"].(map[string]any)
	if !ok || createdRaw["sub1"] == nil {
		t.Fatalf("EmailSubmission/set did not create submission: %v", res)
	}
	var qn int
	sc(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 1 {
		t.Fatalf("expected 1 queued outbound after EmailSubmission/set, got %d", qn)
	}

	// 2. threadId exposed after threading projection folds.
	w := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("thread drain: %v", err)
	}
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+emailID+`"]}, "c3"]`)
	list := g["list"].([]any)
	if len(list) != 1 {
		t.Fatalf("Email/get returned %d, want 1", len(list))
	}
	em := list[0].(map[string]any)
	tid, _ := em["threadId"].(string)
	if !strings.HasPrefix(tid, "T") {
		t.Fatalf("Email/get missing threadId after threading: %v", em["threadId"])
	}
	t.Logf("OK: EmailSubmission/set enqueued to shared queue (1 row); Email/get exposes threadId %q", tid)
}
