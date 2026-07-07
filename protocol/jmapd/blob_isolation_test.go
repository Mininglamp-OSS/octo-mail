package jmapd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestEmailCreateBlobTenantIsolation proves the C1 fix: the tenant id embedded in
// a client-supplied blobId is NOT trusted. Tenant B uploads a blob and gets
// "U<B>-<hash>"; tenant A then attempts Email/set create referencing B's blobId.
// The create must be rejected (not "created"), because emailCreate opens the blob
// only within the authenticated account's own tenant and rejects a mismatch —
// otherwise A could read B's stored bytes.
func TestEmailCreateBlobTenantIsolation(t *testing.T) {
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

	// Two tenants, each with one account.
	var tA, accA, domA, tB, accB, domB int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('ta') RETURNING id`, &tA)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'a') RETURNING id`, &accA, tA)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'a.example') RETURNING id`, &domA, tA)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'a')`, tA, domA, accA)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'a@a.example')`, tA)

	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('tb') RETURNING id`, &tB)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'b') RETURNING id`, &accB, tB)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'b.example') RETURNING id`, &domB, tB)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'b')`, tB, domB, accB)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'b@b.example')`, tB)

	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "a@a.example", "x"); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, "b@b.example", "x"); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test", Blob: bs}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// --- Tenant B uploads a blob → "U<tB>-<hash>". ---
	secret := "From: b@b.example\r\nTo: x@remote.example\r\nSubject: B secret\r\n\r\ntenant B private bytes\r\n"
	upReq, _ := http.NewRequest("POST", hs.URL+"/jmap/upload/"+itoa(accB)+"/", strings.NewReader(secret))
	upReq.SetBasicAuth("b@b.example", "x")
	upReq.Header.Set("Content-Type", "message/rfc822")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatal(err)
	}
	defer upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("B upload status %d, want 201", upResp.StatusCode)
	}
	var up map[string]any
	json.NewDecoder(upResp.Body).Decode(&up)
	bBlobID, _ := up["blobId"].(string)
	if !strings.HasPrefix(bBlobID, "U") {
		t.Fatalf("B blobId = %q, want U-prefixed", bBlobID)
	}

	// --- Tenant A attempts Email/set create referencing B's blobId. ---
	callAs := func(login, methodCallJSON string) map[string]any {
		reqBody := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCallJSON + `]}`
		req, _ := http.NewRequest("POST", hs.URL+"/jmap/api", strings.NewReader(reqBody))
		req.SetBasicAuth(login, "x")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("jmap call: %v", err)
		}
		defer resp.Body.Close()
		var out struct {
			MethodResponses [][3]json.RawMessage `json:"methodResponses"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		var args map[string]any
		if len(out.MethodResponses) > 0 {
			json.Unmarshal(out.MethodResponses[0][1], &args)
		}
		return args
	}

	// Give A a Drafts mailbox so the only failure cause is the blob-tenant check.
	callAs("a@a.example", `["Mailbox/set", {"accountId":"`+itoa(accA)+`","create":{"d":{"name":"Drafts"}}}, "m1"]`)

	res := callAs("a@a.example", `["Email/set", {"accountId":"`+itoa(accA)+`","create":{"steal":{`+
		`"blobId":"`+bBlobID+`","keywords":{"$draft":true}}}}, "c1"]`)

	if created, _ := res["created"].(map[string]any); created != nil && created["steal"] != nil {
		t.Fatalf("C1 LEAK: tenant A created a message from tenant B's blobId %q: %v", bBlobID, created["steal"])
	}
	notCreated, _ := res["notCreated"].(map[string]any)
	if notCreated == nil || notCreated["steal"] == nil {
		t.Fatalf("expected 'steal' in notCreated (rejected), got response: %v", res)
	}

	// Control: A can create from its OWN uploaded blob.
	own := "From: a@a.example\r\nTo: y@remote.example\r\nSubject: A draft\r\n\r\nA body\r\n"
	upA, _ := http.NewRequest("POST", hs.URL+"/jmap/upload/"+itoa(accA)+"/", strings.NewReader(own))
	upA.SetBasicAuth("a@a.example", "x")
	upA.Header.Set("Content-Type", "message/rfc822")
	upAResp, _ := http.DefaultClient.Do(upA)
	var upAo map[string]any
	json.NewDecoder(upAResp.Body).Decode(&upAo)
	upAResp.Body.Close()
	aBlobID, _ := upAo["blobId"].(string)
	res2 := callAs("a@a.example", `["Email/set", {"accountId":"`+itoa(accA)+`","create":{"mine":{`+
		`"blobId":"`+aBlobID+`","keywords":{"$draft":true}}}}, "c2"]`)
	if created, _ := res2["created"].(map[string]any); created == nil || created["mine"] == nil {
		t.Fatalf("A should be able to create from its own blob, got: %v", res2)
	}

	t.Logf("OK: cross-tenant blobId rejected (notCreated), own-tenant blobId accepted — C1 closed")
}
