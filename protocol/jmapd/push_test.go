package jmapd_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestEmailQueryFilterSort proves J-5: Email/query honors filter (from/subject/
// minSize) and sort (size desc), returning ids in the correct order.
func TestEmailQueryFilterSort(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
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
	target, _ := dir.ResolveInbound(ctx, addr.Path())
	// uid1: alice, small; uid2: bob, large; uid3: alice, medium.
	deliver := func(from, subj string, pad int) {
		raw := "From: " + from + "\r\nTo: u1@example.com\r\nSubject: " + subj + "\r\n\r\n" + strings.Repeat("x", pad) + "\r\n"
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}
	deliver("alice@remote.example", "invoice", 10)
	deliver("bob@remote.example", "lunch", 5000)
	deliver("alice@remote.example", "report", 1000)

	// Fold the projection so the denormalized summary columns (subject/from/…)
	// that Email/query's header filters read are populated — same async contract
	// as threadId/fts (recently delivered mail lags until folded).
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// filter from=alice, sort size desc → uid3 (1000) before uid1 (10): ["E3","E1"].
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"from":"alice@remote.example"},"sort":[{"property":"size","isAscending":false}]}, "c1"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 2 || ids[0] != "E3" || ids[1] != "E1" {
		t.Fatalf("filter from=alice sort size desc = %v, want [E3 E1]", ids)
	}

	// filter minSize 2000 → only uid2 (5000).
	q2 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"minSize":2000}}, "c2"]`)
	ids2 := toStrings(q2["ids"])
	if len(ids2) != 1 || ids2[0] != "E2" {
		t.Fatalf("filter minSize=2000 = %v, want [1-2]", ids2)
	}

	// filter subject=lunch → uid2.
	q3 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"subject":"lunch"}}, "c3"]`)
	ids3 := toStrings(q3["ids"])
	if len(ids3) != 1 || ids3[0] != "E2" {
		t.Fatalf("filter subject=lunch = %v, want [1-2]", ids3)
	}

	t.Logf("OK: Email/query from-filter+size-desc-sort, minSize, subject filters all correct")
}

// TestEventSource proves J-6: the /jmap/eventsource SSE channel emits a state
// event on connect and another when a delivery advances the account's changelog.
func TestEventSource(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
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

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Open the SSE stream.
	req, _ := http.NewRequestWithContext(ctx, "GET", hs.URL+"/jmap/eventsource", nil)
	req.SetBasicAuth("u1@example.com", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("eventsource status %d", resp.StatusCode)
	}
	rd := bufio.NewReader(resp.Body)

	readEvent := func() string {
		deadline := time.Now().Add(5 * time.Second)
		var b strings.Builder
		for time.Now().Before(deadline) {
			line, err := rd.ReadString('\n')
			if err != nil {
				return b.String()
			}
			if strings.HasPrefix(line, "data:") {
				return strings.TrimSpace(line)
			}
		}
		return ""
	}

	// Initial state event on connect.
	if ev := readEvent(); !strings.Contains(ev, "StateChange") {
		t.Fatalf("no initial StateChange event: %q", ev)
	}

	// Deliver a message → the coordinator/local Comm should push a new state.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, _ := dir.ResolveInbound(ctx, addr.Path())
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: push\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}

	if ev := readEvent(); !strings.Contains(ev, "StateChange") {
		t.Fatalf("no StateChange event after delivery: %q", ev)
	}
	t.Logf("OK: EventSource emitted initial state + push on delivery (SSE)")
}
