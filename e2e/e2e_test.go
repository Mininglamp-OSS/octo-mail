//go:build e2e

// Package e2e drives the docker-compose stack over the real wire (SMTP/IMAP/
// JMAP/admin HTTP on mapped host ports) and asserts the architecture-review
// findings hold in a deployed octo-mail — not just in unit tests.
//
// Run against a running stack:
//
//	docker compose up -d --build
//	go test -tags e2e ./e2e/ -run TestAcceptance -v
//
// Host ports (see docker-compose.yml): SMTP 2525, submission 5587, IMAP 1143,
// JMAP+webmail 8090, admin+metrics 8091, postgres 15432.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

const (
	adminURL   = "http://localhost:8091"
	jmapURL    = "http://localhost:8090"
	imapAddr   = "localhost:1143"
	adminToken = "e2e-admin-token"
	// Mapped host ports for the deployed stack (see docker-compose.yml).
	pgDSN      = "postgres://octo_mail:octo_mail@localhost:15432/octo_mail?sslmode=disable"
	s3Endpoint = "http://localhost:19010"
	s3Bucket   = "octo-mail"
	s3Access   = "minioadmin"
	s3Secret   = "minioadmin"
)

func admin(t *testing.T, method, path, body string) []byte {
	t.Helper()
	req, err := http.NewRequest(method, adminURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s %s -> %d: %s", method, path, resp.StatusCode, b)
	}
	return b
}

func idOf(b []byte) int64 {
	var r struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(b, &r)
	return r.ID
}

// provisionAccount creates tenant->domain->account->address->password and
// returns the account id. name is used for tenant/account/localpart.
func provisionAccount(t *testing.T, name, domain, login, pw string) int64 {
	t.Helper()
	tid := idOf(admin(t, "POST", "/admin/tenants", fmt.Sprintf(`{"name":%q}`, name)))
	admin(t, "POST", "/admin/domains", fmt.Sprintf(`{"tenant_id":%d,"domain":%q}`, tid, domain))
	aid := idOf(admin(t, "POST", "/admin/accounts", fmt.Sprintf(`{"tenant_id":%d,"name":%q}`, tid, name)))
	admin(t, "POST", "/admin/addresses", fmt.Sprintf(`{"tenant_id":%d,"domain":%q,"localpart":%q,"account":%q}`, tid, domain, strings.Split(login, "@")[0], name))
	admin(t, "POST", "/admin/password", fmt.Sprintf(`{"login":%q,"password":%q}`, login, pw))
	return aid
}

func imapDial(t *testing.T, login, pw string) *imapclient.Conn {
	t.Helper()
	nc, err := net.DialTimeout("tcp", imapAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("imap dial: %v", err)
	}
	c, err := imapclient.New(nc, &imapclient.Opts{Error: func(err error) { t.Logf("imap: %v", err) }})
	if err != nil {
		t.Fatalf("imap greeting: %v", err)
	}
	if _, err := c.AuthenticateSCRAM("SCRAM-SHA-256", sha256.New, login, pw); err != nil {
		t.Fatalf("imap SCRAM auth %s: %v", login, err)
	}
	return c
}

// jmapCall posts a single method call to /jmap/api as login and returns the
// method response arguments (methodResponses[0][1]).
func jmapCall(t *testing.T, login, pw, method string, args map[string]any) map[string]any {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]any{
		"using":       []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
		"methodCalls": [][3]any{{method, args, "c0"}},
	})
	req, _ := http.NewRequest("POST", jmapURL+"/jmap/api", bytes.NewReader(reqBody))
	req.SetBasicAuth(login, pw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jmap %s: %v", method, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("jmap %s -> %d: %s", method, resp.StatusCode, b)
	}
	var out struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("jmap %s decode: %v (%s)", method, err, b)
	}
	if len(out.MethodResponses) == 0 {
		t.Fatalf("jmap %s: empty methodResponses: %s", method, b)
	}
	var name string
	_ = json.Unmarshal(out.MethodResponses[0][0], &name)
	var argsOut map[string]any
	_ = json.Unmarshal(out.MethodResponses[0][1], &argsOut)
	if name == "error" {
		t.Fatalf("jmap %s -> error: %v", method, argsOut)
	}
	return argsOut
}

func waitHealthy(t *testing.T) {
	t.Helper()
	for i := 0; i < 60; i++ {
		resp, err := http.Get(adminURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("stack not healthy after 60s — is docker compose up?")
}

func TestAcceptance(t *testing.T) {
	waitHealthy(t)
	ctx := context.Background()
	_ = ctx

	// Two tenants sharing nothing, to prove cross-tenant isolation over the wire.
	provisionAccount(t, "alice", "acme.test", "alice@acme.test", "alice-pw")
	provisionAccount(t, "bob", "other.test", "bob@other.test", "bob-pw")

	// --- Bob appends a message to his Inbox via IMAP, then we learn his Inbox's
	//     numeric mailbox id via JMAP (needed for the CRIT-1 cross-tenant probe). ---
	bobRaw := "From: x@remote.example\r\nTo: bob@other.test\r\nSubject: bob-secret\r\n\r\nbob body\r\n"
	{
		c := imapDial(t, "bob@other.test", "bob-pw")
		defer c.Close()
		if _, err := c.Append("Inbox", imapclient.Append{Size: int64(len(bobRaw)), Data: strings.NewReader(bobRaw)}); err != nil {
			t.Fatalf("bob APPEND: %v", err)
		}
	}
	var bobInboxID string
	{
		res := jmapCall(t, "bob@other.test", "bob-pw", "Mailbox/get", map[string]any{"accountId": "any"})
		list, _ := res["list"].([]any)
		for _, it := range list {
			m := it.(map[string]any)
			if strings.EqualFold(fmt.Sprint(m["name"]), "Inbox") {
				bobInboxID = fmt.Sprint(m["id"])
			}
		}
		if bobInboxID == "" {
			t.Fatalf("could not find bob's Inbox mailbox id: %v", res)
		}
		t.Logf("bob Inbox mailbox id = %s", bobInboxID)
	}

	// --- CRIT-1: alice runs JMAP Email/query with filter.inMailbox = BOB's mailbox
	//     id. The account-scoped query must return ZERO ids — no cross-tenant leak. ---
	{
		res := jmapCall(t, "alice@acme.test", "alice-pw", "Email/query", map[string]any{
			"accountId": "any",
			"filter":    map[string]any{"inMailbox": bobInboxID},
		})
		ids, _ := res["ids"].([]any)
		total := fmt.Sprint(res["total"])
		if len(ids) != 0 || total != "0" {
			t.Fatalf("CRIT-1 LEAK: alice queried bob's mailbox and got %d ids (total=%s): %v", len(ids), total, ids)
		}
		t.Logf("CRIT-1 OK: alice's query of bob's mailbox id returned 0 rows (no cross-tenant leak)")
	}

	// --- SMELL: alice appends a message with \Seen + $Junk, then reads flags back
	//     via IMAP and keywords via JMAP; the canonical registry must render them
	//     consistently (both surfaces agree the message is seen and junk). ---
	aliceRaw := "From: y@remote.example\r\nTo: alice@acme.test\r\nSubject: alice-msg\r\n\r\nalice body\r\n"
	{
		c := imapDial(t, "alice@acme.test", "alice-pw")
		defer c.Close()
		if _, err := c.Append("Inbox", imapclient.Append{Flags: []string{`\Seen`, `$Junk`}, Size: int64(len(aliceRaw)), Data: strings.NewReader(aliceRaw)}); err != nil {
			t.Fatalf("alice APPEND: %v", err)
		}
		// IMAP FETCH FLAGS.
		if _, err := c.Select("Inbox"); err != nil {
			t.Fatalf("alice SELECT: %v", err)
		}
		if err := c.WriteCommandf("", "uid fetch 1 (FLAGS)"); err != nil {
			t.Fatalf("alice FETCH cmd: %v", err)
		}
		resp, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("alice FETCH resp: %v", err)
		}
		flags := fetchFlags(resp)
		if !flags[`\Seen`] || !flags[`$Junk`] {
			t.Fatalf("SMELL: IMAP flags missing Seen/Junk: %v", flags)
		}
		t.Logf("SMELL OK (IMAP): flags = %v", keys(flags))
	}
	{
		// JMAP Email/query then Email/get keywords — must show $seen and $junk.
		q := jmapCall(t, "alice@acme.test", "alice-pw", "Email/query", map[string]any{"accountId": "any"})
		ids, _ := q["ids"].([]any)
		if len(ids) == 0 {
			t.Fatalf("SMELL: alice Email/query returned no ids")
		}
		g := jmapCall(t, "alice@acme.test", "alice-pw", "Email/get", map[string]any{
			"accountId":  "any",
			"ids":        []any{ids[0]},
			"properties": []any{"keywords"},
		})
		lst, _ := g["list"].([]any)
		if len(lst) == 0 {
			t.Fatalf("SMELL: Email/get returned no message: %v", g)
		}
		kw, _ := lst[0].(map[string]any)["keywords"].(map[string]any)
		if kw["$seen"] != true || kw["$junk"] != true {
			t.Fatalf("SMELL DRIFT: JMAP keywords disagree with IMAP flags: %v", kw)
		}
		t.Logf("SMELL OK (JMAP): keywords = %v — consistent with IMAP", kw)
	}

	t.Logf("ACCEPTANCE PASSED: provisioning + cross-tenant isolation (CRIT-1) + flag/keyword consistency (SMELL) verified over the wire against the deployed stack")
}

func fetchFlags(r imapclient.Response) map[string]bool {
	out := map[string]bool{}
	for _, u := range r.Untagged {
		f, ok := u.(imapclient.UntaggedFetch)
		if !ok {
			continue
		}
		for _, att := range f.Attrs {
			if fa, ok := att.(imapclient.FetchFlags); ok {
				for _, fl := range fa {
					out[string(fl)] = true
				}
			}
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestBlobGC exercises HIGH-2 against the deployed stack end to end: a provisioned
// account receives a message (body written to MinIO/S3), the message is expunged
// via IMAP, and Store.CollectGarbage (run against the mapped Postgres + MinIO)
// hard-deletes the row and reclaims the now-unreferenced object from the bucket.
func TestBlobGC(t *testing.T) {
	waitHealthy(t)
	ctx := context.Background()

	// Fresh account (unique names so the test is rerunnable without a DB reset,
	// as long as the tenant name is new each run is not guaranteed — reset in CI).
	login, pw := "gc@gctenant.test", "gc-pw"
	provisionAccount(t, "gctenant", "gctenant.test", login, pw)

	// Open a Store against the deployed Postgres + MinIO — the SAME backends the
	// running node uses — so CollectGarbage acts on real deployed state.
	bs, err := blob.NewS3(blob.S3Config{Endpoint: s3Endpoint, Region: "us-east-1", Bucket: s3Bucket, AccessKey: s3Access, SecretKey: s3Secret})
	if err != nil {
		t.Fatalf("open s3: %v", err)
	}
	st, err := postgres.Open(ctx, pgDSN, bs)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer st.Close()

	// Append a uniquely-bodied message so its blob ref is unique (reclaimable).
	raw := fmt.Sprintf("From: z@remote.example\r\nTo: %s\r\nSubject: gc-probe\r\n\r\ngc unique body %d\r\n", login, time.Now().UnixNano())
	c := imapDial(t, login, pw)
	defer c.Close()
	if _, err := c.Append("Inbox", imapclient.Append{Size: int64(len(raw)), Data: strings.NewReader(raw)}); err != nil {
		t.Fatalf("APPEND: %v", err)
	}

	// Find its blob_ref + tenant via the DB, and confirm the object exists in S3.
	var tenantID int64
	var ref string
	if err := st.Pool.QueryRow(ctx,
		`SELECT a.tenant_id, m.blob_ref FROM messages m JOIN accounts a ON a.id=m.account_id
		 WHERE m.blob_ref IS NOT NULL ORDER BY m.id DESC LIMIT 1`).Scan(&tenantID, &ref); err != nil {
		t.Fatalf("lookup blob_ref: %v", err)
	}
	if r, err := bs.Open(ctx, tenantID, blob.Ref(ref)); err != nil {
		t.Fatalf("blob should exist in S3 before GC: %v", err)
	} else {
		r.Close()
	}

	// Expunge via IMAP: mark \Deleted then EXPUNGE.
	if _, err := c.Select("Inbox"); err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if err := c.WriteCommandf("", "uid store 1:* +FLAGS (\\Deleted)"); err != nil {
		t.Fatalf("STORE \\Deleted: %v", err)
	}
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("STORE resp: %v", err)
	}
	if _, err := c.Expunge(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}

	// Run GC — the real HIGH-2 code path — against the deployed backends.
	rows, blobs, err := st.CollectGarbage(ctx, 1000)
	if err != nil {
		t.Fatalf("CollectGarbage: %v", err)
	}
	if rows < 1 || blobs < 1 {
		t.Fatalf("GC reclaimed rows=%d blobs=%d, want >=1 each", rows, blobs)
	}

	// The object must be gone from MinIO.
	if r, err := bs.Open(ctx, tenantID, blob.Ref(ref)); err == nil {
		r.Close()
		t.Fatalf("HIGH-2: blob %s still in S3 after GC — not reclaimed", ref)
	}
	t.Logf("HIGH-2 OK: expunged message's body reclaimed from MinIO (rows=%d blobs=%d) against the deployed stack", rows, blobs)
}

// TestAPIKeyAuth proves native API-key auth against the deployed stack: a key
// minted via the store authenticates on the real JMAP HTTP surface with
// Authorization: Bearer omk_..., equivalently to Basic — and a garbage key is
// rejected.
func TestAPIKeyAuth(t *testing.T) {
	waitHealthy(t)
	ctx := context.Background()

	login := "keyagent@keydom.test"
	provisionAccount(t, "keyagent", "keydom.test", login, "key-pw")

	// Mint a key via the store (the operator/CLI path is octo-mail apikey create).
	bs, err := blob.NewS3(blob.S3Config{Endpoint: s3Endpoint, Region: "us-east-1", Bucket: s3Bucket, AccessKey: s3Access, SecretKey: s3Secret})
	if err != nil {
		t.Fatalf("open s3: %v", err)
	}
	st, err := postgres.Open(ctx, pgDSN, bs)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer st.Close()
	token, err := st.NewDirectory().IssueAPIKey(ctx, login, "e2e agent key")
	if err != nil {
		t.Fatalf("IssueAPIKey: %v", err)
	}

	// /jmap/session with Bearer must succeed and identify alice.
	body := bearerGet(t, jmapURL+"/jmap/session", token)
	if !bytes.Contains(body, []byte(login)) {
		t.Fatalf("session with Bearer key did not identify %s: %s", login, body)
	}

	// A JMAP method call with Bearer must work too.
	code := bearerPostStatus(t, jmapURL+"/jmap/api", token,
		`{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"any"},"c0"]]}`)
	if code != 200 {
		t.Fatalf("Bearer JMAP call -> %d, want 200", code)
	}

	// A garbage key must be rejected (401).
	if c := bearerPostStatus(t, jmapURL+"/jmap/api", "omk_deadbeef_nope",
		`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}`); c != 401 {
		t.Fatalf("garbage Bearer key -> %d, want 401", c)
	}
	t.Logf("API-KEY OK: Bearer omk_ key authenticates on JMAP (session + method call) as %s; garbage key rejected", login)
}

// bearerGet does a GET with an Authorization: Bearer header; fails on non-200.
func bearerGet(t *testing.T, url, token string) []byte {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s -> %d: %s", url, resp.StatusCode, b)
	}
	return b
}

// bearerPostStatus POSTs a JSON body with a Bearer header and returns the status.
func bearerPostStatus(t *testing.T, url, token, jsonBody string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
