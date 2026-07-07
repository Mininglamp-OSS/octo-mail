package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// TestTxGetAccountScoped proves the H3 fix: the primary-key fetches Get(*Message)
// and Get(*Mailbox) are scoped to the transaction's account, so a message/mailbox
// id belonging to another account resolves to not-found rather than leaking the
// row (which would carry blob_ref → cross-account body disclosure).
func TestTxGetAccountScoped(t *testing.T) {
	ctx := context.Background()
	s, dir, aliceID := setupTest(t)

	// Second account (bob) in the same tenant, with a delivered message.
	var tenantID int64
	must(t, s.Pool.QueryRow(ctx, `SELECT tenant_id FROM accounts WHERE id=$1`, aliceID).Scan(&tenantID))
	var bobID, bobDom int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'bob') RETURNING id`, tenantID).Scan(&bobID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'bob.example') RETURNING id`, tenantID).Scan(&bobDom))
	_, err := s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'bob')`, tenantID, bobDom, bobID)
	must(t, err)

	// Deliver a message to bob.
	target, err := resolveInbound(t, dir, "bob@bob.example")
	if err != nil {
		t.Fatalf("resolve bob: %v", err)
	}
	bm := &store.Message{}
	if _, err := target.Deliver(ctx, bm, memReader("From: x@remote.example\r\nTo: bob@bob.example\r\nSubject: secret\r\n\r\nbob body\r\n")); err != nil {
		t.Fatalf("deliver to bob: %v", err)
	}
	bobMsgID := bm.ID
	if bobMsgID == 0 {
		t.Fatal("bob message id is 0")
	}

	// Open alice's account and try to Get bob's message + mailbox by raw id.
	alice, _, _, err := s.LookupAccountByID(ctx, aliceID)
	if err != nil {
		t.Fatalf("open alice: %v", err)
	}
	err = alice.Tx(ctx, func(tx store.Tx) error {
		// Message: alice must not see bob's message by its global id.
		m := &store.Message{ID: bobMsgID}
		if e := tx.Get(m); e == nil {
			t.Fatalf("H3: alice Get(bob message id=%d) succeeded — cross-account leak", bobMsgID)
		}
		// Mailbox: bob's Inbox id must not resolve for alice.
		var bobMbID int64
		must(t, s.Pool.QueryRow(ctx, `SELECT mailbox_id FROM messages WHERE id=$1`, bobMsgID).Scan(&bobMbID))
		mb := &store.Mailbox{ID: bobMbID}
		if e := tx.Get(mb); e == nil {
			t.Fatalf("H3: alice Get(bob mailbox id=%d) succeeded — cross-account leak", bobMbID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("alice tx: %v", err)
	}
	t.Logf("OK: cross-account Get(*Message)/Get(*Mailbox) is account-scoped (not-found), no leak")
}

// TestPrincipalLoginGloballyUnique proves the H2 fix: login is unique across all
// tenants, so the same login can't be provisioned in two tenants (which would let
// a client authenticate into the wrong tenant via the global WHERE login=$1
// lookup).
func TestPrincipalLoginGloballyUnique(t *testing.T) {
	ctx := context.Background()
	s, _, aliceID := setupTest(t)

	var t1 int64
	must(t, s.Pool.QueryRow(ctx, `SELECT tenant_id FROM accounts WHERE id=$1`, aliceID).Scan(&t1))
	// First principal in tenant 1.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'dup@example.com')`, t1); err != nil {
		t.Fatalf("insert principal in tenant1: %v", err)
	}
	// A second tenant.
	var t2 int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('other') RETURNING id`).Scan(&t2))
	// Same login in tenant 2 must be rejected by the global unique index.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'dup@example.com')`, t2); err == nil {
		t.Fatal("H2: duplicate login across tenants was allowed — global uniqueness not enforced")
	}
	t.Logf("OK: principals.login is globally unique across tenants")
}
