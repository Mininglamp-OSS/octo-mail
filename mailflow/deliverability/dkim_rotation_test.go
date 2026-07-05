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

// TestDKIMRotationRSAMultiSelector proves P2-3: RSA key generation, multi-selector
// dual-signing (one DKIM-Signature per active selector), and zero-downtime key
// rotation (both selectors verify during overlap; after deactivating the old one,
// only the new selector signs). All verified with the real dkim.Verify.
func TestDKIMRotationRSAMultiSelector(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS dkim_keys (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, domain text NOT NULL, selector text NOT NULL, algo text NOT NULL DEFAULT 'ed25519', private_key bytea NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE (tenant_id, domain, selector))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE dkim_keys RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	// Ensure a tenant row exists (real schema has a FK from dkim_keys.tenant_id).
	const tenant = int64(7)
	var haveFK bool
	pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name='dkim_keys' AND constraint_type='FOREIGN KEY')`).Scan(&haveFK)
	if haveFK {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) OVERRIDING SYSTEM VALUE VALUES ($1,$2) ON CONFLICT (id) DO NOTHING`, tenant, "dkimrot"); err != nil {
			t.Fatal(err)
		}
	}

	const domain = "rotate.example"
	const selOld = "s2025a" // ed25519
	const selNew = "s2025b" // rsa

	// Generate an ed25519 key (old) and an RSA key (new) — both active → dual sign.
	txtOld, err := deliverability.GenerateTenantKey(ctx, pool, tenant, domain, selOld)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	if !strings.Contains(txtOld, "k=ed25519") {
		t.Fatalf("old TXT not ed25519: %q", txtOld)
	}
	txtNew, err := deliverability.GenerateTenantKeyRSA(ctx, pool, nil, tenant, domain, selNew)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	if !strings.Contains(txtNew, "k=rsa") {
		t.Fatalf("new TXT not rsa: %q", txtNew)
	}

	msg := "From: alice@rotate.example\r\n" +
		"To: bob@remote.example\r\n" +
		"Subject: rotation\r\n" +
		"Date: Wed, 01 Jul 2026 10:00:00 +0000\r\n" +
		"Message-Id: <rot1@rotate.example>\r\n" +
		"\r\n" +
		"dual-signed during rotation overlap\r\n"

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			selOld + "._domainkey." + domain + ".": {txtOld},
			selNew + "._domainkey." + domain + ".": {txtNew},
		},
	}
	signer := &deliverability.DKIMSigner{Pool: pool}

	verify := func(header string) []dkim.Result {
		results, err := dkim.Verify(ctx, nil, resolver, false, func(*dkim.Sig) error { return nil }, strings.NewReader(header+msg), false)
		if err != nil {
			t.Fatalf("dkim verify: %v", err)
		}
		return results
	}

	// --- Overlap: both selectors sign, both verify. ---
	h, err := signer.Sign(ctx, tenant, domain, []byte(msg))
	if err != nil {
		t.Fatalf("sign overlap: %v", err)
	}
	if strings.Count(strings.ToLower(h), "dkim-signature:") != 2 {
		t.Fatalf("expected 2 DKIM-Signature headers during overlap, got:\n%s", h)
	}
	res := verify(h)
	if len(res) != 2 {
		t.Fatalf("expected 2 DKIM results during overlap, got %d", len(res))
	}
	sawOld, sawNew, sawRSA, sawEd := false, false, false, false
	for _, r := range res {
		if r.Status != dkim.StatusPass {
			t.Fatalf("overlap signature status = %v (err=%v), want pass", r.Status, r.Err)
		}
		if r.Sig == nil {
			continue
		}
		switch r.Sig.Selector.ASCII {
		case selOld:
			sawOld = true
		case selNew:
			sawNew = true
		}
		switch r.Sig.Algorithm() {
		case "ed25519-sha256":
			sawEd = true
		case "rsa-sha256":
			sawRSA = true
		}
	}
	if !sawOld || !sawNew {
		t.Fatalf("overlap did not sign both selectors: old=%v new=%v", sawOld, sawNew)
	}
	if !sawEd || !sawRSA {
		t.Fatalf("overlap missing an algorithm: ed25519=%v rsa=%v", sawEd, sawRSA)
	}

	// --- Retire the old selector; only the new (RSA) selector should sign now. ---
	if err := deliverability.SetKeyActive(ctx, pool, tenant, domain, selOld, false); err != nil {
		t.Fatalf("deactivate old: %v", err)
	}
	h2, err := signer.Sign(ctx, tenant, domain, []byte(msg))
	if err != nil {
		t.Fatalf("sign after retire: %v", err)
	}
	if strings.Count(strings.ToLower(h2), "dkim-signature:") != 1 {
		t.Fatalf("expected 1 DKIM-Signature after retiring old selector, got:\n%s", h2)
	}
	res2 := verify(h2)
	if len(res2) != 1 || res2[0].Status != dkim.StatusPass {
		t.Fatalf("post-rotation verify failed: %v", res2)
	}
	if res2[0].Sig == nil || res2[0].Sig.Selector.ASCII != selNew {
		t.Fatalf("post-rotation signature not from new selector: %v", res2[0].Sig)
	}

	t.Logf("OK: RSA+ed25519 dual-sign during overlap (both verify), retire old → only new RSA selector signs (verifies)")
}
