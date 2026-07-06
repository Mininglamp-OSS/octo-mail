package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// TestAPIKeyIssueAndAuthenticate proves the native API-key path end to end
// against real Postgres: a minted key authenticates as exactly its own account,
// a wrong/garbage/revoked key is rejected, and a key never resolves to another
// tenant's account (structural isolation holds for Bearer just as for Basic).
func TestAPIKeyIssueAndAuthenticate(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE api_keys, messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	// Provision a full account: tenant -> domain -> account -> address -> principal,
	// mirroring the /admin/* provisioning chain. Returns (tenantID, accountID, login).
	mk := func(name, domain string) (int64, int64, string) {
		var tid, did, aid int64
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, name).Scan(&tid))
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,$2) RETURNING id`, tid, domain).Scan(&did))
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,$2) RETURNING id`, tid, name).Scan(&aid))
		login := name + "@" + domain
		_, err := s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,$4)`, tid, did, aid, name)
		must(t, err)
		_, err = s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,$2)`, tid, login)
		must(t, err)
		return tid, aid, login
	}
	_, aliceAcc, aliceLogin := mk("alice", "acme.test")
	_, _, bobLogin := mk("bob", "other.test")

	dir := s.NewDirectory()

	// Issue a key for alice, then authenticate with it.
	token, err := dir.IssueAPIKey(ctx, aliceLogin, "agent key")
	if err != nil {
		t.Fatalf("IssueAPIKey: %v", err)
	}
	if len(token) < 12 || token[:4] != "omk_" {
		t.Fatalf("token has wrong shape: %q", token)
	}
	scope, princ, accID, err := dir.AuthenticateAPIKey(ctx, token)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey(valid): %v", err)
	}
	if accID != aliceAcc {
		t.Fatalf("key resolved account %d, want alice's %d", accID, aliceAcc)
	}
	if princ.Login != aliceLogin {
		t.Fatalf("principal login = %q, want %q", princ.Login, aliceLogin)
	}
	// The scope must reach alice's account and nothing of another tenant.
	if _, err := scope.Account(ctx, "alice"); err != nil {
		t.Fatalf("scope.Account(alice): %v", err)
	}
	if _, err := scope.Account(ctx, "bob"); err == nil {
		t.Fatalf("alice's key resolved bob's account — cross-tenant leak")
	}

	// Wrong secret (same prefix, tampered tail) must fail.
	bad := token[:len(token)-3] + "xyz"
	if _, _, _, err := dir.AuthenticateAPIKey(ctx, bad); err == nil {
		t.Fatalf("tampered key authenticated")
	}
	// Garbage / non-omk tokens must fail uniformly.
	for _, g := range []string{"", "omk_", "omk_nope", "basic-not-a-key", "omk_aaaa_"} {
		if _, _, _, err := dir.AuthenticateAPIKey(ctx, g); err == nil {
			t.Fatalf("garbage token %q authenticated", g)
		}
	}

	// Revoked key must fail.
	if _, err := s.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE login=$1`, aliceLogin); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := dir.AuthenticateAPIKey(ctx, token); err == nil {
		t.Fatalf("revoked key still authenticated")
	}

	// Issuing for a login with no account/address must error, not panic.
	if _, err := dir.IssueAPIKey(ctx, "nobody@nowhere.test", "x"); err == nil {
		t.Fatalf("IssueAPIKey for unknown login unexpectedly succeeded")
	}
	_ = bobLogin
	t.Logf("OK: API key issues, authenticates as its own account, rejects tampered/garbage/revoked, and cannot reach another tenant")
}
