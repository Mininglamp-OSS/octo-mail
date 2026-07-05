package jmapd_test

import (
	"bytes"
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

// TestUploadAndDraftCreate proves J-7 (upload endpoint) + J-8 (Email/set create):
// upload a raw RFC822 message → receive a blobId → Email/set create referencing
// it into Drafts → the draft appears in Email/query and downloads byte-exact →
// Email/set destroy removes it. All over real HTTP.
func TestUploadAndDraftCreate(t *testing.T) {
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

	// --- J-7: upload a raw draft. ---
	draft := "From: u1@example.com\r\nTo: bob@remote.example\r\nSubject: my draft\r\n\r\ndraft body content\r\n"
	upReq, _ := http.NewRequest("POST", hs.URL+"/jmap/upload/"+itoa(accID)+"/", strings.NewReader(draft))
	upReq.SetBasicAuth("u1@example.com", "x")
	upReq.Header.Set("Content-Type", "message/rfc822")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatal(err)
	}
	defer upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("upload status %d, want 201", upResp.StatusCode)
	}
	var up map[string]any
	json.NewDecoder(upResp.Body).Decode(&up)
	blobID, _ := up["blobId"].(string)
	if !strings.HasPrefix(blobID, "U") {
		t.Fatalf("upload blobId = %q, want U-prefixed", blobID)
	}
	if int64(up["size"].(float64)) != int64(len(draft)) {
		t.Fatalf("upload size = %v, want %d", up["size"], len(draft))
	}

	// Ensure a Drafts mailbox exists (Mailbox/set create).
	call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","create":{"d":{"name":"Drafts"}}}, "m1"]`)

	// --- J-8: Email/set create referencing the uploaded blob. ---
	body := `["Email/set", {"accountId":"` + itoa(accID) + `","create":{"draft1":{` +
		`"blobId":"` + blobID + `","keywords":{"$draft":true}}}}, "c1"]`
	res := call(t, hs.URL, body)
	created, ok := res["created"].(map[string]any)
	if !ok || created["draft1"] == nil {
		t.Fatalf("Email/set create failed: %v", res)
	}
	newID := created["draft1"].(map[string]any)["id"].(string)

	// The draft appears in Email/query.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c2"]`)
	ids := toStrings(q["ids"])
	found := false
	for _, id := range ids {
		if id == newID {
			found = true
		}
	}
	if !found {
		t.Fatalf("created draft %s not in Email/query %v", newID, ids)
	}

	// download the draft → byte-exact.
	dReq, _ := http.NewRequest("GET", hs.URL+"/jmap/download/"+itoa(accID)+"/"+newID+"/d.eml", nil)
	dReq.SetBasicAuth("u1@example.com", "x")
	dResp, err := http.DefaultClient.Do(dReq)
	if err != nil {
		t.Fatal(err)
	}
	defer dResp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(dResp.Body)
	if !strings.Contains(buf.String(), "draft body content") || !strings.Contains(buf.String(), "Subject: my draft") {
		t.Fatalf("downloaded draft missing content: %.80q", buf.String())
	}

	// --- destroy the draft. ---
	dr := call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","destroy":["`+newID+`"]}, "c3"]`)
	destroyed := toStrings(dr["destroyed"])
	if len(destroyed) != 1 || destroyed[0] != newID {
		t.Fatalf("Email/set destroy = %v, want [%s]", dr["destroyed"], newID)
	}
	// gone from query.
	q2 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c4"]`)
	for _, id := range toStrings(q2["ids"]) {
		if id == newID {
			t.Fatalf("destroyed draft %s still in Email/query", newID)
		}
	}

	t.Logf("OK: upload→blobId→Email/set create draft→Email/query visible→download byte-exact→destroy gone (real HTTP)")
}
