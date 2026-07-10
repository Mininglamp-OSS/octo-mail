package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// TestMessageQueryAccountScoped is the regression proof for the CRITICAL-1
// cross-tenant leak: the message query builder must be unconditionally
// constrained to its transaction's account, so that a caller-supplied mailbox id
// belonging to ANOTHER account (as JMAP Email/query's filter.inMailbox once
// allowed) matches zero rows instead of leaking that account's messages.
//
// Setup: two accounts, each with one mailbox holding one message. Opening a Tx
// on account A and filtering by account B's mailbox id must return nothing; the
// unfiltered query on A must see only A's message.
func TestMessageQueryAccountScoped(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	// Two tenants/accounts. Each gets one mailbox and one message, inserted
	// directly so the test targets the query layer, not the write path.
	type acct struct {
		tenantID, accID, mbID, msgID int64
	}
	mk := func(name string) acct {
		var a acct
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, name).Scan(&a.tenantID))
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,$2) RETURNING id`, a.tenantID, name).Scan(&a.accID))
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Inbox',1,2,1,1) RETURNING id`,
			a.accID).Scan(&a.mbID))
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size, received_at, save_date)
			 VALUES ($1,$2,1,1,1,'ref-`+name+`',10, now(), now()) RETURNING id`,
			a.accID, a.mbID).Scan(&a.msgID))
		return a
	}
	a := mk("acct-a")
	b := mk("acct-b")

	accA := s.OpenAccountByID(a.accID, a.tenantID, "acct-a")

	err = accA.Tx(ctx, func(tx store.Tx) error {
		// 1. Filtering by B's mailbox id from A's tx must yield nothing — the
		//    query is account-scoped regardless of the caller-supplied id.
		leaked, e := tx.QueryMessage().FilterMailbox(b.mbID).List()
		if e != nil {
			return e
		}
		if len(leaked) != 0 {
			t.Fatalf("A's query with B's mailbox id returned %d rows — cross-account leak", len(leaked))
		}

		// 2. A's own mailbox id resolves A's single message.
		own, e := tx.QueryMessage().FilterMailbox(a.mbID).List()
		if e != nil {
			return e
		}
		if len(own) != 1 || own[0].ID != a.msgID {
			t.Fatalf("A's own query = %d rows, want 1 (msg %d)", len(own), a.msgID)
		}

		// 3. An unfiltered query from A sees only A's message, never B's.
		all, e := tx.QueryMessage().List()
		if e != nil {
			return e
		}
		for _, m := range all {
			if m.AccountID != a.accID {
				t.Fatalf("A's unfiltered query returned account %d row — cross-account leak", m.AccountID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	t.Logf("OK: message query is account-scoped; a foreign mailbox id matches zero rows (CRITICAL-1 closed)")
}

// TestMessageQueryPushdown proves the H13 query-builder additions: FilterThread
// restricts by thread_id, SortReceivedDesc orders newest-first, and Limit/Offset
// page in SQL. Rows are inserted directly so the test targets the query layer.
func TestMessageQueryPushdown(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, mbID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Inbox',1,10,1,1) RETURNING id`,
		accID).Scan(&mbID))

	// Five messages, uid 1..5, received oldest→newest, threads: 1,1,2,2,2.
	threads := []int64{100, 100, 200, 200, 200}
	ids := make([]int64, 5)
	for i := 0; i < 5; i++ {
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size, thread_id, received_at, save_date)
			 VALUES ($1,$2,$3,$4,$4,'r',10,$5, now() + make_interval(secs => $6), now()) RETURNING id`,
			accID, mbID, i+1, i+1, threads[i], i+1).Scan(&ids[i]))
	}

	acc := s.OpenAccountByID(accID, tenantID, "u")
	err = acc.Tx(ctx, func(tx store.Tx) error {
		// FilterThread: thread 200 has exactly uids 3,4,5.
		th, e := tx.QueryMessage().FilterThread(200).SortUID().List()
		if e != nil {
			return e
		}
		if len(th) != 3 || th[0].UID != 3 || th[2].UID != 5 {
			t.Fatalf("FilterThread(200) = %d rows %v, want uids 3,4,5", len(th), uids(th))
		}

		// SortReceivedDesc: newest-first → uids 5,4,3,2,1.
		desc, e := tx.QueryMessage().SortReceivedDesc().List()
		if e != nil {
			return e
		}
		if len(desc) != 5 || desc[0].UID != 5 || desc[4].UID != 1 {
			t.Fatalf("SortReceivedDesc = %v, want 5,4,3,2,1", uids(desc))
		}

		// Limit+Offset page in SQL: newest-first, skip 1, take 2 → uids 4,3.
		pg, e := tx.QueryMessage().SortReceivedDesc().Limit(2).Offset(1).List()
		if e != nil {
			return e
		}
		if len(pg) != 2 || pg[0].UID != 4 || pg[1].UID != 3 {
			t.Fatalf("SortReceivedDesc Limit(2) Offset(1) = %v, want 4,3", uids(pg))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	t.Logf("OK: FilterThread + SortReceivedDesc + Limit/Offset push filtering/paging into SQL")
}

func uids(ms []store.Message) []store.UID {
	out := make([]store.UID, len(ms))
	for i, m := range ms {
		out[i] = m.UID
	}
	return out
}

// TestMessageQuerySummaryFilters proves the H13 PR2 query-builder pushdowns:
// FilterFrom/Subject (ILIKE on summary columns), FilterSizeRange/ReceivedRange,
// FilterKeyword, DistinctEmail dedup, and Count over the deduped set. Rows are
// inserted directly (columns set) so the test targets the query layer.
func TestMessageQuerySummaryFilters(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, mbID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Inbox',1,10,1,1) RETURNING id`,
		accID).Scan(&mbID))

	ins := func(uid int, from, subj string, size int64, kw []string, folded bool) int64 {
		var id int64
		// from_search mirrors the fold: FilterFrom targets from_search, not the
		// display-only from_addr column.
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size,
			   from_addr, from_search, subject, keywords, summary_folded, received_at, save_date)
			 VALUES ($1,$2,$3,$3,$3,'r',$4,$5,$5,$6,$7,$8, now(), now()) RETURNING id`,
			accID, mbID, uid, size, from, subj, kw, folded).Scan(&id))
		return id
	}
	ins(1, "alice@x.example", "Invoice #5", 100, []string{"$important"}, true)
	ins(2, "bob@x.example", "Lunch plans", 9000, []string{}, true)
	id3 := ins(3, "ALICE@x.example", "re: Invoice", 500, []string{}, true)

	acc := s.OpenAccountByID(accID, tenantID, "u")
	err = acc.Tx(ctx, func(tx store.Tx) error {
		// FilterFrom is case-insensitive substring → both alice rows.
		fr, e := tx.QueryMessage().FilterFrom("alice@").List()
		if e != nil {
			return e
		}
		if len(fr) != 2 {
			return fmtErrf("FilterFrom(alice@) = %d rows, want 2", len(fr))
		}
		// FilterSubject substring.
		sj, _ := tx.QueryMessage().FilterSubject("invoice").List()
		if len(sj) != 2 {
			return fmtErrf("FilterSubject(invoice) = %d, want 2", len(sj))
		}
		// FilterSizeRange.
		sz, _ := tx.QueryMessage().FilterSizeRange(1000, 0).List()
		if len(sz) != 1 || sz[0].UID != 2 {
			return fmtErrf("FilterSizeRange(min=1000) = %v, want uid 2", uids(sz))
		}
		// FilterKeyword has/lacks.
		hk, _ := tx.QueryMessage().FilterKeyword("$important", true).List()
		if len(hk) != 1 || hk[0].UID != 1 {
			return fmtErrf("FilterKeyword($important,true) = %v, want uid 1", uids(hk))
		}
		nk, _ := tx.QueryMessage().FilterKeyword("$important", false).List()
		if len(nk) != 2 {
			return fmtErrf("FilterKeyword($important,false) = %d, want 2", len(nk))
		}
		// LIKE metachars are escaped: "%" matches nothing (no literal % in data).
		pc, _ := tx.QueryMessage().FilterSubject("%").List()
		if len(pc) != 0 {
			return fmtErrf("FilterSubject(%%) = %d, want 0 (escaped)", len(pc))
		}
		// Count matches List length for a filter.
		n, _ := tx.QueryMessage().FilterFrom("alice@").Count()
		if n != 2 {
			return fmtErrf("Count(FilterFrom alice@) = %d, want 2", n)
		}
		_ = id3
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OK: from/subject/size/keyword filters + escaping + Count all correct")
}

// TestMessageQueryDistinctEmail proves DistinctEmail collapses sibling rows of one
// Email (shared email_id) so Count and List page over Emails, not rows.
func TestMessageQueryDistinctEmail(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, mb1, mb2 int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Inbox',1,10,1,1) RETURNING id`, accID).Scan(&mb1))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO mailboxes (account_id, name, uidvalidity, uidnext, createseq, modseq) VALUES ($1,'Archive',1,10,1,1) RETURNING id`, accID).Scan(&mb2))

	// One standalone Email (id A) and one Email present in two mailboxes (the
	// original id B in Inbox + a sibling in Archive with email_id=B).
	var a, b int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size, summary_folded, received_at, save_date) VALUES ($1,$2,1,1,1,'r',10,true, now(), now()) RETURNING id`, accID, mb1).Scan(&a))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size, summary_folded, received_at, save_date) VALUES ($1,$2,2,2,2,'r',10,true, now(), now()) RETURNING id`, accID, mb1).Scan(&b))
	if _, err := s.Pool.Exec(ctx, `INSERT INTO messages (account_id, mailbox_id, uid, createseq, modseq, blob_ref, size, email_id, summary_folded, received_at, save_date) VALUES ($1,$2,1,3,3,'r',10,$3,true, now(), now())`, accID, mb2, b); err != nil {
		t.Fatal(err)
	}

	acc := s.OpenAccountByID(accID, tenantID, "u")
	err = acc.Tx(ctx, func(tx store.Tx) error {
		// 3 rows, but 2 Emails.
		all, _ := tx.QueryMessage().List()
		if len(all) != 3 {
			return fmtErrf("rows = %d, want 3", len(all))
		}
		n, _ := tx.QueryMessage().DistinctEmail().Count()
		if n != 2 {
			return fmtErrf("DistinctEmail Count = %d, want 2 Emails", n)
		}
		ded, _ := tx.QueryMessage().DistinctEmail().SortReceivedDesc().List()
		if len(ded) != 2 {
			return fmtErrf("DistinctEmail List = %d, want 2", len(ded))
		}
		_ = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OK: DistinctEmail collapses sibling rows to one Email for Count + List")
}

func fmtErrf(f string, a ...any) error { return fmt.Errorf(f, a...) }
