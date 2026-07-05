package jmapd_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestJMAPBreadth proves the J-round additions over real HTTP: Email/get rich
// properties (subject/from/to/receivedAt/bodyStructure/bodyValues), Thread/get,
// Mailbox/set (create+destroy), and the blob download endpoint.
func TestJMAPBreadth(t *testing.T) {
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

	// Deliver a reply chain (root + reply) so threading groups them.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	root := "Message-ID: <root@example.com>\r\nFrom: Alice <alice@remote.example>\r\nTo: u1@example.com\r\nSubject: hello world\r\n\r\nthis is the body text\r\n"
	reply := "Message-ID: <r1@example.com>\r\nIn-Reply-To: <root@example.com>\r\nReferences: <root@example.com>\r\nFrom: Bob <bob@remote.example>\r\nTo: u1@example.com\r\nSubject: Re: hello world\r\n\r\nreply body\r\n"
	for _, raw := range []string{root, reply} {
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}
	// Fold the threading projection so threadId/Thread-get work.
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// --- J-1: Email/get rich properties for the root message (uid 1). ---
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+"E1"+`"]}, "c1"]`)
	em := g["list"].([]any)[0].(map[string]any)
	if em["subject"] != "hello world" {
		t.Fatalf("Email/get subject = %v, want 'hello world'", em["subject"])
	}
	from := em["from"].([]any)
	if len(from) != 1 || from[0].(map[string]any)["email"] != "alice@remote.example" {
		t.Fatalf("Email/get from = %v, want alice@remote.example", em["from"])
	}
	if em["receivedAt"] == nil {
		t.Fatalf("Email/get missing receivedAt")
	}
	if em["bodyStructure"] == nil {
		t.Fatalf("Email/get missing bodyStructure")
	}
	bv, ok := em["bodyValues"].(map[string]any)
	if !ok || len(bv) == 0 {
		t.Fatalf("Email/get missing bodyValues: %v", em["bodyValues"])
	}
	foundBody := false
	for _, v := range bv {
		if strings.Contains(v.(map[string]any)["value"].(string), "this is the body text") {
			foundBody = true
		}
	}
	if !foundBody {
		t.Fatalf("bodyValues did not contain body text: %v", bv)
	}
	threadID, _ := em["threadId"].(string)
	if !strings.HasPrefix(threadID, "T") {
		t.Fatalf("Email/get missing threadId")
	}

	// --- J-2: Thread/get returns both emails of the conversation. ---
	tg := call(t, hs.URL, `["Thread/get", {"accountId":"`+itoa(accID)+`","ids":["`+threadID+`"]}, "c2"]`)
	tl := tg["list"].([]any)
	if len(tl) != 1 {
		t.Fatalf("Thread/get returned %d threads, want 1", len(tl))
	}
	emails := tl[0].(map[string]any)["emailIds"].([]any)
	if len(emails) != 2 {
		t.Fatalf("Thread/get emailIds = %v, want 2 (root+reply)", emails)
	}

	// --- J-3: Mailbox/set create then destroy. ---
	cr := call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","create":{"m1":{"name":"Archive2025"}}}, "c3"]`)
	created := cr["created"].(map[string]any)
	if created["m1"] == nil {
		t.Fatalf("Mailbox/set create failed: %v", cr)
	}
	newMbID := created["m1"].(map[string]any)["id"].(string)
	// Verify it appears in Mailbox/get.
	mg := call(t, hs.URL, `["Mailbox/get", {"accountId":"`+itoa(accID)+`"}, "c4"]`)
	foundMb := false
	for _, m := range mg["list"].([]any) {
		if m.(map[string]any)["name"] == "Archive2025" {
			foundMb = true
		}
	}
	if !foundMb {
		t.Fatalf("created mailbox not in Mailbox/get")
	}
	// Destroy it.
	dr := call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","destroy":["`+newMbID+`"]}, "c5"]`)
	destroyed := dr["destroyed"].([]any)
	if len(destroyed) != 1 || destroyed[0] != newMbID {
		t.Fatalf("Mailbox/set destroy = %v, want [%s]", dr["destroyed"], newMbID)
	}

	// --- J-4: blob download returns the raw message bytes. ---
	req, _ := http.NewRequest("GET", hs.URL+"/jmap/download/"+itoa(accID)+"/E1/msg.eml", nil)
	req.SetBasicAuth("u1@example.com", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download status %d", resp.StatusCode)
	}
	dl, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(dl), "this is the body text") || !strings.Contains(string(dl), "Subject: hello world") {
		t.Fatalf("download did not return full message: %.80q", string(dl))
	}

	t.Logf("OK: Email/get rich props + Thread/get(2) + Mailbox/set create/destroy + blob download all correct over real HTTP")
}
