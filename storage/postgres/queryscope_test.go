package postgres

import (
	"context"
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
