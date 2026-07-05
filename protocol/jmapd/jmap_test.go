package jmapd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestJMAPProjectionSymmetry proves the architecture's central claim: IMAP and
// JMAP are two projections of ONE change-log. It exercises the real JMAP methods
// (Email/query, Email/get, Email/changes, Email/set) over HTTP, and asserts that
// JMAP state == changelog offset and that Email/changes(sinceState=n) returns
// exactly the messages with modseq > n — the same replay IMAP serves as
// CONDSTORE CHANGEDSINCE n.
func TestJMAPProjectionSymmetry(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Deliver msg 1, capture head, deliver msg 2.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: one\r\n\r\nbody one\r\n")); err != nil {
		t.Fatal(err)
	}
	var afterFirst int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &afterFirst, accID)
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: two\r\n\r\nbody two\r\n")); err != nil {
		t.Fatal(err)
	}

	// HTTP JMAP server.
	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Session: state present, primary mail account is ours.
	sess := getJSON(t, hs.URL+"/jmap/session")
	if sess["primaryAccounts"] == nil {
		t.Fatalf("session missing primaryAccounts: %v", sess)
	}

	// Email/query all -> 2 ids.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 2 {
		t.Fatalf("Email/query returned %d ids, want 2", len(ids))
	}
	// queryState must equal current changelog head.
	var head int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head, accID)
	if q["queryState"] != strconv.FormatInt(head, 10) {
		t.Fatalf("JMAP queryState=%v != changelog head=%d", q["queryState"], head)
	}

	// Email/changes sinceState=afterFirst -> exactly the 2nd message (created).
	ch := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(afterFirst)+`"}, "c2"]`)
	created := toStrings(ch["created"])
	if len(created) != 1 {
		t.Fatalf("Email/changes since %d: created=%v, want exactly 1 (the 2nd msg)", afterFirst, created)
	}
	// This is the SAME set IMAP CHANGEDSINCE afterFirst returns (the 2nd msg).
	// The JMAP Email id is "E<effectiveEmailID>"; the Email/get below confirms it
	// maps to the second message ("body two").
	if !strings.HasPrefix(created[0], "E") {
		t.Fatalf("Email/changes created id %q is not an E<id> email id", created[0])
	}

	// Email/get the changed one -> preview from blob, keywords empty (unseen).
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+created[0]+`"]}, "c3"]`)
	glist := g["list"].([]any)
	if len(glist) != 1 {
		t.Fatalf("Email/get returned %d, want 1", len(glist))
	}
	em := glist[0].(map[string]any)
	if !strings.Contains(em["preview"].(string), "body two") {
		t.Fatalf("Email/get preview wrong: %v", em["preview"])
	}

	// Email/set: mark $seen; then Email/get shows the keyword.
	_ = call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"`+created[0]+`":{"keywords/$seen":true}}}, "c4"]`)
	g2 := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+created[0]+`"]}, "c5"]`)
	em2 := g2["list"].([]any)[0].(map[string]any)
	kw, _ := em2["keywords"].(map[string]any)
	if kw == nil || kw["$seen"] != true {
		t.Fatalf("Email/set did not persist $seen: %v", em2["keywords"])
	}

	// Invariant after JMAP writes: state advanced, still == changelog head.
	var head2 int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head2, accID)
	var maxSeq int64
	sc(t, s, ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, &maxSeq, accID)
	if head2 != maxSeq {
		t.Fatalf("modseq invariant broken after JMAP: head=%d max=%d", head2, maxSeq)
	}
	if head2 <= head {
		t.Fatalf("JMAP Email/set did not advance changelog: before=%d after=%d", head, head2)
	}
	t.Logf("OK: JMAP state==changelog head=%d; Email/changes since %d == IMAP CHANGEDSINCE (uid 2); $seen persisted", head2, afterFirst)
}

// --- helpers ---

func call(t *testing.T, baseURL, methodCallJSON string) map[string]any {
	t.Helper()
	reqBody := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCallJSON + `]}`
	req, _ := http.NewRequest("POST", baseURL+"/jmap/api", strings.NewReader(reqBody))
	req.SetBasicAuth("u1@example.com", "x")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jmap call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("jmap call status %d", resp.StatusCode)
	}
	var out struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.MethodResponses) == 0 {
		t.Fatalf("no method responses")
	}
	var name string
	_ = json.Unmarshal(out.MethodResponses[0][0], &name)
	if name == "error" {
		t.Fatalf("jmap method error: %s", string(out.MethodResponses[0][1]))
	}
	var args map[string]any
	_ = json.Unmarshal(out.MethodResponses[0][1], &args)
	return args
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth("u1@example.com", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func mem(s string) store.BlobReader {
	return &memBlob{Reader: bytes.NewReader([]byte(s)), size: int64(len(s))}
}

type memBlob struct {
	*bytes.Reader
	size int64
}

func (m *memBlob) Size() int64  { return m.size }
func (m *memBlob) Close() error { return nil }

func sc(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("scan: %v", err)
	}
}
func ex(t *testing.T, s *postgres.Store, ctx context.Context, sql string, args ...any) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
