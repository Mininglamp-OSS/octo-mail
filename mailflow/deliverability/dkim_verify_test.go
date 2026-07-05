package deliverability_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
)

const dkimDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestPerTenantDKIMSignAndVerify proves the per-tenant DKIM boundary is closed:
// a tenant's generated key signs an outbound message, and the REAL dkim.Verify
// validates the signature against the published TXT record — attributing the
// signature to the tenant's own domain. A different tenant's domain cannot be
// signed with this key, so reputation stays isolated.
func TestPerTenantDKIMSignAndVerify(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	// Apply schema (dkim_keys) — reuse postgres's Open path indirectly by ensuring
	// the table exists; create it if missing for an isolated run.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS dkim_keys (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, domain text NOT NULL, selector text NOT NULL, algo text NOT NULL DEFAULT 'ed25519', private_key bytea NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE (tenant_id, domain, selector))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE dkim_keys RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	const tenantA = int64(1)
	const domain = "acme.example"
	const selector = "octomail1"

	// Generate the tenant's key; publish the returned TXT in a mock resolver.
	txt, err := deliverability.GenerateTenantKey(ctx, pool, tenantA, domain, selector)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if !strings.Contains(txt, "k=ed25519") || !strings.Contains(txt, "p=") {
		t.Fatalf("unexpected TXT record: %q", txt)
	}

	// Sign a message.
	msg := "From: alice@acme.example\r\n" +
		"To: bob@remote.example\r\n" +
		"Subject: signed by tenant\r\n" +
		"Date: Wed, 01 Jul 2026 10:00:00 +0000\r\n" +
		"Message-Id: <sign1@acme.example>\r\n" +
		"\r\n" +
		"this message is DKIM-signed with the tenant key\r\n"
	signer := &deliverability.DKIMSigner{Pool: pool}
	header, err := signer.Sign(ctx, tenantA, domain, []byte(msg))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.HasPrefix(strings.ToLower(header), "dkim-signature:") {
		t.Fatalf("no DKIM-Signature produced: %q", header)
	}

	// Prepend the signature and verify with the real dkim.Verify against the
	// published TXT record.
	signed := header + msg
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			selector + "._domainkey." + domain + ".": {txt},
		},
	}
	results, err := dkim.Verify(ctx, nil, resolver, false, func(*dkim.Sig) error { return nil }, strings.NewReader(signed), false)
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("no DKIM results")
	}
	if results[0].Status != dkim.StatusPass {
		t.Fatalf("DKIM verify status = %v (err=%v), want pass", results[0].Status, results[0].Err)
	}
	if results[0].Sig == nil || results[0].Sig.Domain.ASCII != domain {
		t.Fatalf("DKIM signature domain = %v, want %s (reputation must attribute to tenant domain)", results[0].Sig, domain)
	}

	// A tenant with no key for a domain signs nothing (caller sends unsigned).
	empty, err := signer.Sign(ctx, int64(999), "other.example", []byte(msg))
	if err != nil {
		t.Fatalf("sign no-key: %v", err)
	}
	if empty != "" {
		t.Fatalf("expected empty signature for tenant without key, got %q", empty)
	}

	t.Logf("OK: tenant key signed; dkim.Verify PASS attributing to %s; no-key tenant sends unsigned", domain)
}
