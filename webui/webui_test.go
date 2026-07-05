package webui_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/Mininglamp-OSS/octo-mail/webui"
	"github.com/mjl-/mox/smtp"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestWebmailEndToEnd proves P0-2: the webmail SPA is served (HTML + app.js),
// and the exact JMAP flow the SPA performs — session login, list Inbox, read a
// message, and send (upload+Email/set+EmailSubmission) — works against a live
// jmapd. This drives the same HTTP calls app.ts makes, so a browser loading the
// served assets would function.
func TestWebmailEndToEnd(t *testing.T) {
	ctx := context.Background()

	// 1. The SPA assets are served.
	ws := httptest.NewServer(webui.Handler())
	defer ws.Close()
	idx, err := http.Get(ws.URL + "/webmail/")
	if err != nil || idx.StatusCode != 200 {
		t.Fatalf("index: err=%v status=%v", err, idx)
	}
	idxBody, _ := io.ReadAll(idx.Body)
	idx.Body.Close()
	if !strings.Contains(string(idxBody), "octo-mail webmail") || !strings.Contains(string(idxBody), "app.js") {
		t.Fatalf("index.html missing expected content")
	}
	js, err := http.Get(ws.URL + "/webmail/app.js")
	if err != nil || js.StatusCode != 200 {
		t.Fatalf("app.js: err=%v status=%v", err, js)
	}
	jsBody, _ := io.ReadAll(js.Body)
	js.Body.Close()
	if !bytes.Contains(jsBody, []byte("jmap")) {
		t.Fatalf("app.js does not look like the compiled client")
	}

	// 2. The JMAP flow the SPA drives works end to end.
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	// Deliver one inbox message to list/read.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, _ := dir.ResolveInbound(ctx, addr.Path())
	target.Deliver(ctx, &store.Message{}, memBlob("From: bob@remote.example\r\nTo: u1@example.com\r\nSubject: hi there\r\n\r\nbody text\r\n"))

	js2 := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test", Blob: bs, Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	js2srv := httptest.NewServer(js2.Handler())
	defer js2srv.Close()

	auth := "Basic " + basicAuth("u1@example.com", "pw")
	// session (login)
	sess := getJSON(t, js2srv.URL+"/jmap/session", auth)
	acc := sess["primaryAccounts"].(map[string]any)["urn:ietf:params:jmap:mail"].(string)
	// Email/query INBOX
	q := jmapCall(t, js2srv.URL, auth, `["Email/query",{"accountId":"`+acc+`"},"c0"]`)
	ids := q["ids"].([]any)
	if len(ids) != 1 {
		t.Fatalf("inbox list = %d, want 1", len(ids))
	}
	// Email/get (read)
	g := jmapCall(t, js2srv.URL, auth, `["Email/get",{"accountId":"`+acc+`","ids":["`+ids[0].(string)+`"]},"c0"]`)
	em := g["list"].([]any)[0].(map[string]any)
	if em["subject"] != "hi there" {
		t.Fatalf("read subject = %v", em["subject"])
	}
	// send: upload + Email/set create + EmailSubmission
	raw := "From: u1@example.com\r\nTo: carol@remote.example\r\nSubject: reply\r\n\r\nsent from webmail\r\n"
	up, _ := http.NewRequest("POST", js2srv.URL+"/jmap/upload/"+acc+"/", strings.NewReader(raw))
	up.Header.Set("Authorization", auth)
	up.Header.Set("Content-Type", "message/rfc822")
	upResp, err := http.DefaultClient.Do(up)
	if err != nil || upResp.StatusCode != 201 {
		t.Fatalf("upload: err=%v status=%v", err, upResp.StatusCode)
	}
	var upj map[string]any
	json.NewDecoder(upResp.Body).Decode(&upj)
	upResp.Body.Close()
	blobID := upj["blobId"].(string)
	cr := jmapCall(t, js2srv.URL, auth, `["Email/set",{"accountId":"`+acc+`","create":{"c1":{"blobId":"`+blobID+`","keywords":{"$draft":true}}}},"c0"]`)
	emailID := cr["created"].(map[string]any)["c1"].(map[string]any)["id"].(string)
	sub := jmapCall(t, js2srv.URL, auth, `["EmailSubmission/set",{"accountId":"`+acc+`","create":{"s1":{"emailId":"`+emailID+`","envelope":{"mailFrom":{"email":"u1@example.com"},"rcptTo":[{"email":"carol@remote.example"}]}}}},"c0"]`)
	if sub["created"].(map[string]any)["s1"] == nil {
		t.Fatalf("submission failed: %v", sub)
	}
	var queued int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&queued)
	if queued != 1 {
		t.Fatalf("send did not enqueue: queue=%d", queued)
	}

	t.Logf("OK: webmail assets served (HTML+app.js); SPA JMAP flow works — login→list(1)→read('hi there')→send(enqueued)")
}

// --- helpers ---

func basicAuth(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}

func getJSON(t *testing.T, url, auth string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func jmapCall(t *testing.T, base, auth, methodCall string) map[string]any {
	t.Helper()
	body := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCall + `]}`
	req, _ := http.NewRequest("POST", base+"/jmap/api", strings.NewReader(body))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	var args map[string]any
	json.Unmarshal(out.MethodResponses[0][1], &args)
	return args
}

func memBlob(s string) store.BlobReader { return &mb{data: []byte(s)} }

type mb struct {
	data []byte
	off  int64
}

func (m *mb) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *mb) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *mb) Size() int64  { return int64(len(m.data)) }
func (m *mb) Close() error { return nil }
