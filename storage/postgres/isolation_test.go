package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/security/auth"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// TestTenantScopeIsolation is the adversarial authorization proof for WF2: an
// authenticated principal's TenantScope can reach ONLY its own tenant's objects.
// It sets up two tenants that share a localpart and account name, authenticates
// as tenant A, and shows that every scope accessor either returns A's object or
// nothing — never B's. The structural claim ("a handler holding A's scope has no
// reference through which to name B") is enforced at runtime here: even asking
// for B's exact domain/account name from A's scope yields A's data or an error.
func TestTenantScopeIsolation(t *testing.T) {
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

	// Two tenants, each with a domain, an account named "shared", and an address
	// shared@<their-domain>. Same names on purpose — isolation must not rely on
	// names being distinct.
	type ten struct {
		id, accID, domID int64
		domain, login    string
	}
	mk := func(name, domain, login string) ten {
		var x ten
		x.domain, x.login = domain, login
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, name).Scan(&x.id))
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'shared') RETURNING id`, x.id).Scan(&x.accID))
		must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,$2) RETURNING id`, x.id, domain).Scan(&x.domID))
		_, err := s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'shared')`, x.id, x.domID, x.accID)
		must(t, err)
		// Principal for tenant with a real password.
		cred, err := auth.HashPassword("pw-" + name)
		must(t, err)
		credJSON, err := cred.Marshal()
		must(t, err)
		_, err = s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login, cred) VALUES ($1,$2,$3)`, x.id, login, credJSON)
		must(t, err)
		return x
	}
	a := mk("tenant-a", "a.example", "shared@a.example")
	b := mk("tenant-b", "b.example", "shared@b.example")

	dir := s.NewDirectory()

	// Authenticate as tenant A. The returned scope is bound to A.
	scopeA, princ, err := dir.AuthenticatePrincipal(ctx, a.login, directory.PasswordCredential("pw-tenant-a"))
	if err != nil {
		t.Fatalf("auth as A: %v", err)
	}
	if scopeA.Tenant().ID != a.id {
		t.Fatalf("scope bound to tenant %d, want A=%d", scopeA.Tenant().ID, a.id)
	}
	if princ.TenantID != a.id {
		t.Fatalf("principal bound to tenant %d, want A=%d", princ.TenantID, a.id)
	}

	// 1. Account("shared") from A's scope resolves to A's account, never B's —
	//    even though both tenants have an account literally named "shared".
	accA, err := scopeA.Account(ctx, "shared")
	if err != nil {
		t.Fatalf("A.Account(shared): %v", err)
	}
	if accA.ID() == b.accID {
		t.Fatalf("A's scope returned B's account (id=%d) — cross-tenant leak", b.accID)
	}
	if accA.ID() != a.accID {
		t.Fatalf("A.Account(shared) = %d, want A's %d", accA.ID(), a.accID)
	}

	// 2. AccountForAddress for B's exact address from A's scope must NOT resolve
	//    (A's scope filters by tenant_id=A; B's address lives under tenant B).
	bAddr, err := smtp.ParseAddress("shared@b.example")
	must(t, err)
	if _, err := scopeA.AccountForAddress(ctx, bAddr.Path()); err == nil {
		t.Fatalf("A's scope resolved B's address shared@b.example — cross-tenant leak")
	}
	// A's own address still resolves to A's account.
	aAddr, err := smtp.ParseAddress("shared@a.example")
	must(t, err)
	accA2, err := scopeA.AccountForAddress(ctx, aAddr.Path())
	if err != nil {
		t.Fatalf("A.AccountForAddress(own): %v", err)
	}
	if accA2.ID() != a.accID {
		t.Fatalf("A.AccountForAddress(own) = %d, want %d", accA2.ID(), a.accID)
	}

	// 3. Domain lookup for B's domain from A's scope must fail.
	if _, err := scopeA.Domain(ctx, dns.Domain{ASCII: "b.example"}); err == nil {
		t.Fatalf("A's scope resolved B's domain b.example — cross-tenant leak")
	}

	// 4. Accounts() from A's scope lists only A's accounts.
	accs, err := scopeA.Accounts(ctx)
	if err != nil {
		t.Fatalf("A.Accounts: %v", err)
	}
	for _, ac := range accs {
		if ac.ID() == b.accID {
			t.Fatalf("A.Accounts() included B's account — cross-tenant leak")
		}
	}

	// 5. Wrong tenant's password never authenticates the other's login.
	if _, _, err := dir.AuthenticatePrincipal(ctx, a.login, directory.PasswordCredential("pw-tenant-b")); err == nil {
		t.Fatalf("A's login authenticated with B's password")
	}

	t.Logf("OK: tenant A's scope reaches only A's account/address/domain; B is unreachable by name (structural isolation enforced at runtime)")
}
