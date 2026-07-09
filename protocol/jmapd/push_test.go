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

// TestEmailQueryFilterUnfolded proves the H13 PR2 hybrid filter fallback: a
// from/subject filter finds a message that has been delivered but NOT yet folded
// by the summary projection (its summary columns are still empty). Without the
// live fallback the SQL column filter would silently drop it.
func TestEmailQueryFilterUnfolded(t *testing.T) {
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
	// Deliver a message from a display-named sender, but DO NOT fold: summary
	// columns stay empty, exercising the live fallback.
	raw := "From: Alice Smith <alice@remote.example>\r\nTo: u1@example.com\r\nSubject: quarterly report\r\n\r\nbody\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// from-filter on the address must find the unfolded message.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"from":"alice@remote.example"}}, "c1"]`)
	if ids := toStrings(q["ids"]); len(ids) != 1 || ids[0] != "E1" {
		t.Fatalf("from filter on unfolded msg = %v, want [E1] (live fallback missing)", ids)
	}
	// subject filter likewise.
	q2 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"subject":"quarterly"}}, "c2"]`)
	if ids := toStrings(q2["ids"]); len(ids) != 1 || ids[0] != "E1" {
		t.Fatalf("subject filter on unfolded msg = %v, want [E1]", ids)
	}
	// display-name filter: "Alice Smith" must match via the live envelope (name).
	q3 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"from":"Alice Smith"}}, "c3"]`)
	if ids := toStrings(q3["ids"]); len(ids) != 1 || ids[0] != "E1" {
		t.Fatalf("display-name filter on unfolded msg = %v, want [E1]", ids)
	}

	// After folding, the same filters still match (now via columns) — no dupes.
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}
	q4 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"from":"Alice Smith"}}, "c4"]`)
	if ids := toStrings(q4["ids"]); len(ids) != 1 || ids[0] != "E1" {
		t.Fatalf("after fold, display-name filter = %v, want [E1] (column path, no dupes)", ids)
	}
	t.Logf("OK: from/subject/display-name filters find an unfolded message (live fallback); same after fold, deduped")
}

// TestEmailQueryTotalAndPaging proves Email/query reports an accurate total (via
// Count, not a capped page length) and pages correctly with position/limit — the
// regression where total was len(rows) over a 1000-capped set.
func TestEmailQueryTotalAndPaging(t *testing.T) {
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
	const n = 12
	for i := 0; i < n; i++ {
		raw := "From: s@remote.example\r\nTo: u1@example.com\r\nSubject: m" + itoa(int64(i)) + "\r\n\r\nbody\r\n"
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 100}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Unfiltered query, limit 5: total must be the full 12 (Count), page = 5.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","limit":5}, "c1"]`)
	if tot := int(q["total"].(float64)); tot != n {
		t.Fatalf("total = %d, want %d (accurate Count, not page length)", tot, n)
	}
	if ids := toStrings(q["ids"]); len(ids) != 5 {
		t.Fatalf("page = %d ids, want 5", len(ids))
	}
	// Deep page: position 10, limit 5 → 2 remaining.
	q2 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","position":10,"limit":5}, "c2"]`)
	if tot := int(q2["total"].(float64)); tot != n {
		t.Fatalf("deep-page total = %d, want %d", tot, n)
	}
	if ids := toStrings(q2["ids"]); len(ids) != 2 {
		t.Fatalf("position=10 page = %d ids, want 2", len(ids))
	}
	t.Logf("OK: Email/query total accurate (%d) via Count; position/limit paging correct", n)
}

// TestEmailQueryKeywordTotalNoDoubleCount proves B-A's fix: with a keyword filter
// spanning folded and unfolded rows, `total` counts each matching row once. The
// keyword column is written at delivery (independent of summary_folded), so the
// SQL keyword predicate matches unfolded rows too — before the fix those rows
// were counted both in the SQL total and the live fallback, inflating `total`.
func TestEmailQueryKeywordTotalNoDoubleCount(t *testing.T) {
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
	const n = 4
	for i := 0; i < n; i++ {
		raw := "From: s@remote.example\r\nTo: u1@example.com\r\nSubject: m" + itoa(int64(i)) + "\r\n\r\nbody\r\n"
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}
	// Put a custom keyword on ALL rows (written to the keywords array, independent
	// of the summary projection).
	if _, err := s.Pool.Exec(ctx,
		`UPDATE messages SET keywords=ARRAY['important'] WHERE account_id=$1`, accID); err != nil {
		t.Fatal(err)
	}
	// Fold only the FIRST 2 rows; leave 2 unfolded, so the query exercises both the
	// SQL (folded) and live (unfolded) paths for the same keyword.
	if _, err := s.Pool.Exec(ctx,
		`UPDATE messages SET summary_folded=true WHERE account_id=$1 AND id IN (
		    SELECT id FROM messages WHERE account_id=$1 ORDER BY id LIMIT 2)`, accID); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// hasKeyword: total must be exactly 4 (2 folded + 2 live), not 6 (double count),
	// and ids must be the 4 distinct messages.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"hasKeyword":"important"}}, "c1"]`)
	if tot := int(q["total"].(float64)); tot != n {
		t.Fatalf("hasKeyword total = %d, want %d (unfolded keyword rows double-counted)", tot, n)
	}
	if ids := toStrings(q["ids"]); len(ids) != n {
		t.Fatalf("hasKeyword ids = %d, want %d", len(ids), n)
	}

	// notKeyword worst case: no row has 'other', so all 4 match. Before the fix,
	// matchesLiveFilter short-circuits true for every unfolded row → those 2 are
	// double-counted → total 6.
	q2 := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"notKeyword":"other"}}, "c2"]`)
	if tot := int(q2["total"].(float64)); tot != n {
		t.Fatalf("notKeyword total = %d, want %d (unfolded rows double-counted on notKeyword)", tot, n)
	}
	t.Logf("OK: keyword filter total counts folded+unfolded rows once (no double count) for hasKeyword and notKeyword")
}

// TestEmailQueryCopiedEmailTotalNoDoubleCount proves the email-group-dimension
// fix: a copied (multi-mailbox) message has two rows sharing one email_id. When
// one sibling is folded and the other is not (the fold-lag window), the folded
// row lands in foldedTotal and the unfolded row lands in the live set — the same
// Email counted twice by a row-level partition. total must dedup on the email
// group, so a single copied Email reports total=1 (matching its single id).
func TestEmailQueryCopiedEmailTotalNoDoubleCount(t *testing.T) {
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
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Message-ID: <m@example.com>\r\nFrom: alice@remote.example\r\nTo: u1@example.com\r\nSubject: shared\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Copy the email into a second mailbox → two rows sharing one email_id.
	cr := call(t, hs.URL, `["Mailbox/set", {"accountId":"`+itoa(accID)+`","create":{"a":{"name":"Archive"}}}, "c1"]`)
	archiveID := cr["created"].(map[string]any)["a"].(map[string]any)["id"].(string)
	call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"E1":{"mailboxIds/`+archiveID+`":true}}}, "c2"]`)
	var nRows int
	sc(t, s, ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, &nRows, accID)
	if nRows != 2 {
		t.Fatalf("precondition: want 2 rows (copied email), got %d", nRows)
	}

	// Put a custom keyword on BOTH rows, and fold EXACTLY ONE sibling — the
	// straddling state: one folded row + one unfolded row, same email_id.
	ex(t, s, ctx, `UPDATE messages SET keywords=ARRAY['important'] WHERE account_id=$1`, accID)
	ex(t, s, ctx, `UPDATE messages SET summary_folded=true, subject='shared', from_search='alice@remote.example'
	     WHERE account_id=$1 AND id=(SELECT min(id) FROM messages WHERE account_id=$1)`, accID)
	ex(t, s, ctx, `UPDATE messages SET summary_folded=false WHERE account_id=$1 AND id=(SELECT max(id) FROM messages WHERE account_id=$1)`, accID)

	// hasKeyword: one Email, folded+unfolded siblings — total must be 1, not 2.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`","filter":{"hasKeyword":"important"}}, "c3"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 1 {
		t.Fatalf("copied-email hasKeyword ids = %v, want exactly [E1] (one Email)", ids)
	}
	if tot := int(q["total"].(float64)); tot != 1 {
		t.Fatalf("copied-email hasKeyword total = %d, want 1 (email-group double-count: folded+unfolded siblings)", tot)
	}
	// total must equal len(ids) — the internal-consistency invariant RFC 8621 paging relies on.
	if tot := int(q["total"].(float64)); tot != len(ids) {
		t.Fatalf("total (%d) != len(ids) (%d) — inconsistent", tot, len(ids))
	}
	t.Logf("OK: a copied email straddling the fold boundary is counted once in total (email-group dedup)")
}
