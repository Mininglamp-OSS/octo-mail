package deliverability_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
)

// TestDKIMKeyEncryptionAtRest proves WF7 key encryption: a DKIM private key
// written with a KeyCipher is NOT stored as usable plaintext (a DB dump cannot
// sign), a signer with the correct master secret decrypts and signs (verified by
// the verifier), and a signer with the wrong secret fails.
func TestDKIMKeyEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS dkim_keys (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, domain text NOT NULL, selector text NOT NULL, algo text NOT NULL DEFAULT 'ed25519', private_key bytea NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE (tenant_id, domain, selector))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE dkim_keys RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	cipher, err := deliverability.NewKeyCipher([]byte("correct-master-secret"))
	if err != nil {
		t.Fatal(err)
	}
	const tenant = int64(1)
	const domain = "enc.example"
	const selector = "e1"

	txt, err := deliverability.GenerateTenantKeyEnc(ctx, pool, cipher, tenant, domain, selector)
	if err != nil {
		t.Fatal(err)
	}

	// The stored key must be ciphertext (magic-prefixed), not a raw 64-byte key.
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT private_key FROM dkim_keys WHERE tenant_id=$1`, tenant).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) == 64 {
		t.Fatalf("private key stored as raw 64-byte plaintext — encryption not applied")
	}
	if !bytes.HasPrefix(stored, []byte("MENC2")) {
		t.Fatalf("stored key lacks encryption magic prefix: %x", stored[:min(8, len(stored))])
	}

	msg := "From: a@enc.example\r\nTo: b@remote.example\r\nSubject: enc\r\nDate: Wed, 01 Jul 2026 10:00:00 +0000\r\nMessage-Id: <e1@enc.example>\r\n\r\nbody\r\n"

	// Correct cipher: signs, dkim.Verify confirms PASS.
	good := &deliverability.DKIMSigner{Pool: pool, Cipher: cipher}
	hdr, err := good.Sign(ctx, tenant, domain, []byte(msg))
	if err != nil {
		t.Fatalf("sign with correct cipher: %v", err)
	}
	if hdr == "" {
		t.Fatalf("no signature produced")
	}
	resolver := dns.MockResolver{TXT: map[string][]string{
		selector + "._domainkey." + domain + ".": {txt},
	}}
	results, err := dkim.Verify(ctx, nil, resolver, false, func(*dkim.Sig) error { return nil }, bytes.NewReader([]byte(hdr+msg)), false)
	if err != nil || len(results) == 0 || results[0].Status != dkim.StatusPass {
		t.Fatalf("verify with correct cipher failed: err=%v results=%v", err, results)
	}

	// Wrong master secret: cannot decrypt, sign fails (no forged signature).
	wrongCipher, _ := deliverability.NewKeyCipher([]byte("WRONG-master-secret"))
	bad := &deliverability.DKIMSigner{Pool: pool, Cipher: wrongCipher}
	if _, err := bad.Sign(ctx, tenant, domain, []byte(msg)); err == nil {
		t.Fatalf("sign succeeded with WRONG master secret — key encryption ineffective")
	}

	// No cipher at all against encrypted key: also fails (not silently plaintext).
	none := &deliverability.DKIMSigner{Pool: pool}
	if _, err := none.Sign(ctx, tenant, domain, []byte(msg)); err == nil {
		t.Fatalf("sign succeeded with NO cipher against encrypted key")
	}

	t.Logf("OK: DKIM key encrypted at rest (MENC2); correct secret signs+verifies; wrong/absent secret cannot sign")
}

// TestDKIMKeyAADBinding proves the #25-3 AAD binding: a key encrypted for one
// (tenant, domain, selector) row cannot be decrypted with any OTHER tuple, so a
// ciphertext lifted from one row into another (a DB tamper) fails to decrypt
// rather than silently signing under the wrong identity. Exercised through the
// public Generate/Sign path: a stored ciphertext whose row identity is altered
// no longer decrypts.
func TestDKIMKeyAADBinding(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS dkim_keys (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, domain text NOT NULL, selector text NOT NULL, algo text NOT NULL DEFAULT 'ed25519', private_key bytea NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE (tenant_id, domain, selector))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE dkim_keys RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	cipher, err := deliverability.NewKeyCipher([]byte("master-secret"))
	if err != nil {
		t.Fatal(err)
	}
	// dkim_keys FKs tenant_id → tenants(id) in the real schema; seed a tenant.
	var tenant int64
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('aad-t') RETURNING id`).Scan(&tenant); err != nil {
		t.Skipf("cannot seed tenant (%v)", err)
	}
	const domain = "aad.example"
	const selector = "s1"
	if _, err := deliverability.GenerateTenantKeyEnc(ctx, pool, cipher, tenant, domain, selector); err != nil {
		t.Fatal(err)
	}

	// Tamper: change the row's selector so the AAD reconstructed at Sign time no
	// longer matches what encrypt bound. The ciphertext is intact but the tag must
	// now fail — proving the key is bound to its identity.
	if _, err := pool.Exec(ctx, `UPDATE dkim_keys SET selector='s2' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	msg := "From: a@aad.example\r\nSubject: x\r\n\r\nbody\r\n"
	signer := &deliverability.DKIMSigner{Pool: pool, Cipher: cipher}
	if _, err := signer.Sign(ctx, tenant, domain, []byte(msg)); err == nil {
		t.Fatalf("Sign succeeded after the row's selector was altered — AAD not binding identity (a lifted ciphertext would sign)")
	}
	t.Logf("OK: a DKIM ciphertext is bound to its (tenant,domain,selector) via GCM AAD; altering the row's identity breaks decryption")
}
