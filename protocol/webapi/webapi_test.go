package webapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestRESTAPI exercises the resource-oriented REST surface (/webapi/v0) end to
// end over real HTTP against a real PostgreSQL: per-account auth (401 without
// credentials), send (202 → outbound queue), list/get/raw, flag via PATCH,
// thread get, suppression PUT/GET/list/DELETE, and message DELETE (204 → 404).
func TestRESTAPI(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, suppressions RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "pw"); err != nil {
		t.Fatal(err)
	}

	// Deliver one message so the message resource has something to operate on.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: friend@remote.example\r\nTo: u1@example.com\r\nSubject: hi\r\nMessage-ID: <orig@remote.example>\r\n\r\nbody here\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &webapi.Server{
		Dir:          dir,
		Submission:   &submit.Submitter{Pool: s.Pool, Blob: bs},
		Suppressions: &deliverability.Suppressions{Pool: s.Pool},
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	// do issues an authenticated request and returns (status, decoded-json).
	do := func(method, path, body string) (int, map[string]any) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, hs.URL+path, rd)
		req.SetBasicAuth("u1@example.com", "pw")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		raw, _ := io.ReadAll(resp.Body)
		if len(bytes.TrimSpace(raw)) > 0 {
			json.Unmarshal(raw, &out)
		}
		if e, ok := out["error"]; ok {
			t.Fatalf("%s %s → %d error: %v", method, path, resp.StatusCode, e)
		}
		return resp.StatusCode, out
	}

	// --- auth: no credentials → 401. ---
	{
		resp, _ := http.Get(hs.URL + "/webapi/v0/mailboxes")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request status = %d, want 401", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// --- mailboxes: Inbox present. ---
	st, mb := do("GET", "/webapi/v0/mailboxes", "")
	if st != http.StatusOK {
		t.Fatalf("GET mailboxes status = %d, want 200", st)
	}
	if !hasMailbox(mb["mailboxes"], "Inbox") {
		t.Fatalf("mailboxes missing Inbox: %v", mb["mailboxes"])
	}

	// --- list: the delivered message shows up; capture its id. ---
	st, lst := do("GET", "/webapi/v0/messages", "")
	if st != http.StatusOK {
		t.Fatalf("GET messages status = %d, want 200", st)
	}
	msgs, _ := lst["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("list returned %d messages, want 1", len(msgs))
	}
	m0 := msgs[0].(map[string]any)
	id, _ := m0["id"].(string)
	if id == "" || id[0] != 'E' {
		t.Fatalf("message id = %q, want E<n>", id)
	}
	if m0["unread"] != true {
		t.Fatalf("new message should be unread: %v", m0)
	}

	// --- get: bodies + subject. ---
	st, get := do("GET", "/webapi/v0/messages/"+id, "")
	if st != http.StatusOK {
		t.Fatalf("GET message status = %d, want 200", st)
	}
	if get["subject"] != "hi" || !strings.Contains(toString(get["bodyText"]), "body here") {
		t.Fatalf("GET message unexpected: subject=%v body=%v", get["subject"], get["bodyText"])
	}

	// --- raw: message/rfc822 bytes. ---
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+id+"/raw", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "message/rfc822" {
			t.Fatalf("raw content-type = %q, want message/rfc822", ct)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(raw, []byte("body here")) {
			t.Fatalf("raw did not return body: %.60q", raw)
		}
	}

	// --- send: 202 + submissionIds, one queue row. ---
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/messages",
			strings.NewReader(`{"to":["dst@remote.example"],"subject":"hello","text":"greetings"}`))
		req.SetBasicAuth("u1@example.com", "pw")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST messages status = %d, want 202", resp.StatusCode)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if ids, _ := out["submissionIds"].([]any); len(ids) != 1 {
			t.Fatalf("send submissionIds = %v, want 1", out["submissionIds"])
		}
	}
	var qn int
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 1 {
		t.Fatalf("queue rows = %d, want 1 after send", qn)
	}

	// --- reply: derives recipient + threading, enqueues. ---
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/messages/"+id+"/reply",
			strings.NewReader(`{"text":"thanks"}`))
		req.SetBasicAuth("u1@example.com", "pw")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST reply status = %d, want 202", resp.StatusCode)
		}
		resp.Body.Close()
	}
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 2 {
		t.Fatalf("queue rows = %d, want 2 after reply", qn)
	}

	// --- flag via PATCH: add \Seen, becomes read. ---
	do("PATCH", "/webapi/v0/messages/"+id, `{"addKeywords":["\\Seen"]}`)
	_, get2 := do("GET", "/webapi/v0/messages/"+id, "")
	if get2["unread"] != false {
		t.Fatalf("after \\Seen PATCH, unread = %v, want false", get2["unread"])
	}

	// --- thread get: the message belongs to a thread. ---
	if tid, _ := get2["threadId"].(string); tid != "" {
		st, th := do("GET", "/webapi/v0/threads/"+tid, "")
		if st != http.StatusOK {
			t.Fatalf("GET thread status = %d, want 200", st)
		}
		if tmsgs, _ := th["messages"].([]any); len(tmsgs) < 1 {
			t.Fatalf("thread returned no messages: %v", th)
		}
	}

	// --- suppressions: PUT (idempotent) / GET / list / DELETE. ---
	st, _ = do("PUT", "/webapi/v0/suppressions/bad@remote.example", `{"reason":"bounce"}`)
	if st != http.StatusOK {
		t.Fatalf("PUT suppression status = %d, want 200", st)
	}
	st, _ = do("GET", "/webapi/v0/suppressions/bad@remote.example", "")
	if st != http.StatusOK {
		t.Fatalf("GET suppression presence status = %d, want 200", st)
	}
	_, sl := do("GET", "/webapi/v0/suppressions", "")
	if sups, _ := sl["suppressions"].([]any); len(sups) != 1 || sups[0] != "bad@remote.example" {
		t.Fatalf("suppression list = %v, want [bad@remote.example]", sl["suppressions"])
	}
	{
		req, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/suppressions/bad@remote.example", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE suppression status = %d, want 204", resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Absent now → 404.
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/suppressions/bad@remote.example", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET removed suppression status = %d, want 404", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// --- delete message: 204, then GET → 404. ---
	{
		req, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/messages/"+id, nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE message status = %d, want 204", resp.StatusCode)
		}
		resp.Body.Close()
	}
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+id, nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET deleted message status = %d, want 404", resp.StatusCode)
		}
		resp.Body.Close()
	}

	t.Logf("OK: REST auth + mailboxes + list/get/raw + send/reply(enqueue) + PATCH flag + thread + suppressions + delete over real HTTP")
}

func scan(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatal(err)
	}
}

func hasMailbox(v any, name string) bool {
	list, _ := v.([]any)
	for _, x := range list {
		if mb, ok := x.(map[string]any); ok && mb["name"] == name {
			return true
		}
	}
	return false
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func mem(s string) store.BlobReader {
	return &memBlob{Reader: bytes.NewReader([]byte(s)), n: int64(len(s))}
}

type memBlob struct {
	*bytes.Reader
	n int64
}

func (m *memBlob) Close() error { return nil }
func (m *memBlob) Size() int64  { return m.n }
