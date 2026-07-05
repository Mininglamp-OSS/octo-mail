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

// TestWebAPIEndToEnd proves P3 webapi (production-parity HTTP/JSON RPC over the kernel):
// per-account auth; Send enqueues to the shared outbound queue; Suppression*
// add/present/list/remove; and Message* get/flags/delete over a real delivered
// message — all over real HTTP.
func TestWebAPIEndToEnd(t *testing.T) {
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

	// Deliver one message so Message* has something to operate on.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: hi\r\n\r\nbody here\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &webapi.Server{
		Dir:          dir,
		Submission:   &submit.Submitter{Pool: s.Pool, Blob: bs},
		Suppressions: &deliverability.Suppressions{Pool: s.Pool},
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	call := func(method string, reqBody string) map[string]any {
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/"+method, strings.NewReader(reqBody))
		req.SetBasicAuth("u1@example.com", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		if e, ok := out["Error"].(map[string]any); ok {
			t.Fatalf("%s returned error: %v", method, e)
		}
		return out
	}

	// --- auth: no credentials → 401. ---
	{
		resp, _ := http.Post(hs.URL+"/webapi/v0/SuppressionList", "application/json", strings.NewReader("{}"))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request status = %d, want 401", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// --- Send: enqueues to the shared outbound queue. ---
	sendRes := call("Send", `{"From":{"Address":"u1@example.com"},"To":[{"Address":"dst@remote.example"}],"Subject":"hello","Text":"greetings"}`)
	sub, ok := sendRes["Submission"].([]any)
	if !ok || len(sub) != 1 {
		t.Fatalf("Send did not enqueue exactly one message: %v", sendRes["Submission"])
	}
	var qn int
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 1 {
		t.Fatalf("queue rows = %d, want 1 after Send", qn)
	}

	// --- Suppression add / present / list / remove. ---
	call("SuppressionAdd", `{"Address":"bad@remote.example","Reason":"bounce"}`)
	pres := call("SuppressionPresent", `{"Address":"bad@remote.example"}`)
	if pres["Present"] != true {
		t.Fatalf("SuppressionPresent = %v, want true", pres["Present"])
	}
	lst := call("SuppressionList", `{}`)
	sups, _ := lst["Suppressions"].([]any)
	if len(sups) != 1 || sups[0] != "bad@remote.example" {
		t.Fatalf("SuppressionList = %v, want [bad@remote.example]", lst["Suppressions"])
	}
	call("SuppressionRemove", `{"Address":"bad@remote.example"}`)
	pres2 := call("SuppressionPresent", `{"Address":"bad@remote.example"}`)
	if pres2["Present"] != false {
		t.Fatalf("SuppressionPresent after remove = %v, want false", pres2["Present"])
	}

	// --- Message get / flags add / raw get / delete. ---
	get := call("MessageGet", `{"Mailbox":"Inbox","UID":1}`)
	if get["Size"] == nil || get["Mailbox"] != "Inbox" {
		t.Fatalf("MessageGet unexpected: %v", get)
	}
	call("MessageFlagsAdd", `{"Mailbox":"Inbox","UID":1,"Flags":["\\Seen"]}`)
	get2 := call("MessageGet", `{"Mailbox":"Inbox","UID":1}`)
	flags, _ := get2["Flags"].([]any)
	sawSeen := false
	for _, f := range flags {
		if f == `\Seen` {
			sawSeen = true
		}
	}
	if !sawSeen {
		t.Fatalf("MessageFlagsAdd did not set \\Seen: %v", get2["Flags"])
	}

	// MessageRawGet returns the raw RFC822 (message/rfc822 content type).
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/MessageRawGet", strings.NewReader(`{"Mailbox":"Inbox","UID":1}`))
		req.SetBasicAuth("u1@example.com", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(raw, []byte("body here")) {
			t.Fatalf("MessageRawGet did not return the message body: %.60q", raw)
		}
	}

	// Delete the message; MessageGet then fails (user error, not crash).
	call("MessageDelete", `{"Mailbox":"Inbox","UID":1}`)
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/MessageGet", strings.NewReader(`{"Mailbox":"Inbox","UID":1}`))
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if _, ok := out["Error"]; !ok {
			t.Fatalf("MessageGet after delete should error, got %v", out)
		}
	}

	t.Logf("OK: webapi auth + Send(enqueue) + Suppression add/present/list/remove + Message get/flags/raw/delete over real HTTP")
}

func scan(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatal(err)
	}
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
