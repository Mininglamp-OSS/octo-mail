package jmapd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestJMAPRequestLimits proves the H11 DoS guards: the /jmap/api body is bounded
// (oversized → 413, not buffered), the method-call batch is capped at the
// advertised maxCallsInRequest (over-long → 413, no dispatch), and /jmap/upload
// is bounded at maxSizeUpload. A request within the limits still succeeds.
func TestJMAPRequestLimits(t *testing.T) {
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

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test", Blob: bs}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	post := func(path, body string) int {
		req, _ := http.NewRequest("POST", hs.URL+path, strings.NewReader(body))
		req.SetBasicAuth("u1@example.com", "x")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// A well-formed, in-limits request still works (Core/echo is always safe).
	ok := `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"c0"]]}`
	if code := post("/jmap/api", ok); code != http.StatusOK {
		t.Fatalf("in-limits api request → %d, want 200", code)
	}

	// Over-long method batch (> maxCallsInRequest=64) is rejected before dispatch.
	var calls []string
	for i := 0; i < 65; i++ {
		calls = append(calls, fmt.Sprintf(`["Core/echo",{},"c%d"]`, i))
	}
	tooMany := `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[` + strings.Join(calls, ",") + `]}`
	if code := post("/jmap/api", tooMany); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("65-call batch → %d, want 413", code)
	}

	// Oversized api body (> maxAPIRequestSize=10 MiB) is rejected, not buffered.
	huge := `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"pad":"` +
		strings.Repeat("A", 11<<20) + `"},"c0"]]}`
	if code := post("/jmap/api", huge); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("11 MiB api body → %d, want 413", code)
	}

	// Oversized upload (> maxSizeUpload=50 MB) is rejected.
	upReq, _ := http.NewRequest("POST", hs.URL+"/jmap/upload/"+itoa(accID)+"/",
		strings.NewReader(strings.Repeat("A", 50_000_001)))
	upReq.SetBasicAuth("u1@example.com", "x")
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer upResp.Body.Close()
	if upResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("50MB+1 upload → %d, want 413", upResp.StatusCode)
	}

	// Per-object cap: an Email/get with > maxObjectsInGet (1000) ids is rejected
	// with a method-level requestTooLarge error BEFORE any DB fetch — closing the
	// single-call amplification vector (~1M ids fit under the 10 MiB body cap).
	methodErr := func(body string) string {
		req, _ := http.NewRequest("POST", hs.URL+"/jmap/api", strings.NewReader(body))
		req.SetBasicAuth("u1@example.com", "x")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("api status %d, want 200 (method-level error)", resp.StatusCode)
		}
		var out struct {
			MethodResponses [][3]json.RawMessage `json:"methodResponses"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.MethodResponses) == 0 {
			t.Fatalf("decode: %v", err)
		}
		var name string
		_ = json.Unmarshal(out.MethodResponses[0][0], &name)
		var args map[string]any
		_ = json.Unmarshal(out.MethodResponses[0][1], &args)
		if name == "error" {
			if t, _ := args["type"].(string); t != "" {
				return t
			}
		}
		return name
	}
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf(`"E%d"`, i+1)
	}
	overGet := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/get",{"accountId":"` +
		itoa(accID) + `","ids":[` + strings.Join(ids, ",") + `]},"c0"]]}`
	if got := methodErr(overGet); got != "requestTooLarge" {
		t.Fatalf("Email/get with 1001 ids → %q, want requestTooLarge", got)
	}

	t.Logf("OK: api body/batch/upload bounded (413); per-object get cap enforced (requestTooLarge); in-limits request still 200")
}
