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
	if !bytes.HasPrefix(stored, []byte("MENC1")) {
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

	t.Logf("OK: DKIM key encrypted at rest (MENC1); correct secret signs+verifies; wrong/absent secret cannot sign")
}
