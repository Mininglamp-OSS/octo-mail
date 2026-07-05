package jmapd_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestSearchSnippet proves JMAP SearchSnippet/get (RFC 8621 §5.6): for a given
// filter term and emailIds, the server returns per-email subject + preview
// snippets with the term wrapped in <mark>...</mark> — the search-hit context a
// JMAP client renders under each result. Verified over real HTTP.
func TestSearchSnippet(t *testing.T) {
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

	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Body has the search term "invoice" in a specific context; subject has it too.
	raw := "Message-ID: <m@example.com>\r\nFrom: Alice <alice@remote.example>\r\nTo: u1@example.com\r\nSubject: Your invoice is ready\r\n\r\n" +
		"Dear customer, please find attached the invoice for last month. The invoice total is due in 14 days.\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	res := call(t, hs.URL, `["SearchSnippet/get", {"accountId":"`+itoa(accID)+`","filter":{"text":"invoice"},"emailIds":["E1"]}, "c1"]`)
	list, ok := res["list"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("SearchSnippet/get list = %v, want 1 entry", res["list"])
	}
	snip := list[0].(map[string]any)
	if snip["emailId"] != "E1" {
		t.Fatalf("snippet emailId = %v, want E1", snip["emailId"])
	}
	subject, _ := snip["subject"].(string)
	preview, _ := snip["preview"].(string)
	// Subject match highlighted.
	if !strings.Contains(strings.ToLower(subject), "<mark>invoice</mark>") {
		t.Fatalf("subject not highlighted: %q", subject)
	}
	// Preview contains the highlighted term and surrounding body context.
	if !strings.Contains(strings.ToLower(preview), "<mark>invoice</mark>") {
		t.Fatalf("preview not highlighted: %q", preview)
	}
	if !strings.Contains(strings.ToLower(preview), "customer") && !strings.Contains(strings.ToLower(preview), "total") {
		t.Fatalf("preview missing body context: %q", preview)
	}

	// A term absent from the body still returns a snippet (leading excerpt), no <mark>.
	res2 := call(t, hs.URL, `["SearchSnippet/get", {"accountId":"`+itoa(accID)+`","filter":{"text":"zzznotpresent"},"emailIds":["E1"]}, "c2"]`)
	snip2 := res2["list"].([]any)[0].(map[string]any)
	if strings.Contains(snip2["preview"].(string), "<mark>") {
		t.Fatalf("absent term should not produce <mark>: %q", snip2["preview"])
	}

	t.Logf("OK: SearchSnippet/get highlighted 'invoice' in subject+preview with <mark>; absent term returned plain excerpt")
}
