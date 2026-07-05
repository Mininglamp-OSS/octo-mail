package deliverability

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// DKIMSigner signs outbound messages with a per-tenant, per-domain key loaded
// from the dkim_keys table. Signing with the tenant's own key means the
// resulting reputation accrues to that tenant's domain — never the platform's or
// another tenant's. This closes the "per-tenant DKIM" boundary from P5, where
// the table existed but nothing signed.
//
// All *active* keys for (tenant, domain) are used, so a message carries one
// DKIM-Signature per active selector. This is what makes zero-downtime key
// rotation work: publish the new selector's DNS TXT, activate the new key
// alongside the old (both sign), let receivers cache the new record, then
// deactivate the old. During the overlap every message validates under either.
type DKIMSigner struct {
	Pool *pgxpool.Pool
	// Cipher, if set, decrypts private keys read from dkim_keys (keys written by
	// GenerateTenantKey with the same cipher). Nil = keys are stored plaintext.
	Cipher *KeyCipher
}

// GenerateTenantKey creates an ed25519 DKIM key for (tenant, domain, selector)
// and stores the private key, returning the public-key TXT record the operator
// must publish at <selector>._domainkey.<domain>. Idempotent via upsert. If
// cipher is non-nil the private key is encrypted at rest.
func GenerateTenantKey(ctx context.Context, pool *pgxpool.Pool, tenantID int64, domain, selector string) (string, error) {
	return GenerateTenantKeyEnc(ctx, pool, nil, tenantID, domain, selector)
}

// GenerateTenantKeyEnc is GenerateTenantKey with optional at-rest encryption.
func GenerateTenantKeyEnc(ctx context.Context, pool *pgxpool.Pool, cipher *KeyCipher, tenantID int64, domain, selector string) (string, error) {
	return generateKey(ctx, pool, cipher, tenantID, domain, selector, "ed25519")
}

// GenerateTenantKeyRSA creates a 2048-bit RSA DKIM key. RSA is still the most
// broadly-supported DKIM algorithm; some receivers do not yet validate ed25519,
// so a domain may publish both (dual signing via multiple active selectors).
func GenerateTenantKeyRSA(ctx context.Context, pool *pgxpool.Pool, cipher *KeyCipher, tenantID int64, domain, selector string) (string, error) {
	return generateKey(ctx, pool, cipher, tenantID, domain, selector, "rsa")
}

func generateKey(ctx context.Context, pool *pgxpool.Pool, cipher *KeyCipher, tenantID int64, domain, selector, algo string) (string, error) {
	var der []byte // PKCS8 private key bytes to store
	var txt string // public-key TXT record to publish
	switch algo {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		d, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", err
		}
		der = d
		txt = "v=DKIM1;k=ed25519;p=" + base64.StdEncoding.EncodeToString(pub)
	case "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		d, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", err
		}
		der = d
		pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return "", err
		}
		txt = "v=DKIM1;k=rsa;p=" + base64.StdEncoding.EncodeToString(pubDER)
	default:
		return "", fmt.Errorf("unsupported dkim algo %q", algo)
	}

	stored, err := cipher.encrypt(der)
	if err != nil {
		return "", err
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO dkim_keys (tenant_id, domain, selector, algo, private_key, active)
		 VALUES ($1,$2,$3,$4,$5,true)
		 ON CONFLICT (tenant_id, domain, selector)
		 DO UPDATE SET private_key=EXCLUDED.private_key, algo=EXCLUDED.algo, active=true`,
		tenantID, domain, selector, algo, stored); err != nil {
		return "", err
	}
	return txt, nil
}

// SetKeyActive flips a selector's active flag. Deactivating retires an old
// selector after rotation; activating brings a freshly-published one into the
// signing set. Both operations are used by the rotation dance.
func SetKeyActive(ctx context.Context, pool *pgxpool.Pool, tenantID int64, domain, selector string, active bool) error {
	tag, err := pool.Exec(ctx,
		`UPDATE dkim_keys SET active=$4 WHERE tenant_id=$1 AND domain=$2 AND selector=$3`,
		tenantID, domain, selector, active)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no dkim key for %s selector %s", domain, selector)
	}
	return nil
}

// Sign returns the DKIM-Signature header line(s) for a message, using ALL of the
// tenant's active keys for fromDomain (one signature per active selector). msg is
// the full RFC822 message. Returns "" (no error) when the tenant has no active
// key — the caller then sends unsigned.
func (d *DKIMSigner) Sign(ctx context.Context, tenantID int64, fromDomain string, msg []byte) (string, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT selector, algo, private_key FROM dkim_keys
		 WHERE tenant_id=$1 AND domain=$2 AND active ORDER BY id`,
		tenantID, fromDomain)
	if err != nil {
		return "", err
	}
	type keyRow struct {
		selector, algo string
		priv           []byte
	}
	var krs []keyRow
	for rows.Next() {
		var kr keyRow
		if err := rows.Scan(&kr.selector, &kr.algo, &kr.priv); err != nil {
			rows.Close()
			return "", err
		}
		krs = append(krs, kr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(krs) == 0 {
		return "", nil
	}

	dom, err := dns.ParseDomain(fromDomain)
	if err != nil {
		return "", err
	}

	var selectors []dkim.Selector
	for _, kr := range krs {
		privBytes, err := d.Cipher.decrypt(kr.priv)
		if err != nil {
			return "", fmt.Errorf("decrypt dkim key: %w", err)
		}
		signer, err := parseSigner(kr.algo, privBytes)
		if err != nil {
			return "", err
		}
		selectors = append(selectors, dkim.Selector{
			Hash:          "sha256",
			HeaderRelaxed: true,
			BodyRelaxed:   true,
			Headers:       []string{"From", "To", "Subject", "Date", "Message-Id"},
			PrivateKey:    signer,
			Domain:        dns.Domain{ASCII: kr.selector},
		})
	}

	headers, err := dkim.Sign(ctx, nil, smtp.Localpart("postmaster"), dom, selectors, false, bytes.NewReader(msg))
	if err != nil {
		return "", err
	}
	return headers, nil
}

// parseSigner turns stored private-key bytes into a crypto.Signer. New keys are
// PKCS8 DER (both ed25519 and RSA). Legacy ed25519 keys were stored as the raw
// 64-byte seed+public form; those are still accepted.
func parseSigner(algo string, priv []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(priv); err == nil {
		switch k := key.(type) {
		case ed25519.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unexpected pkcs8 key type %T", key)
		}
	}
	// Legacy raw ed25519 private key.
	if algo == "ed25519" && len(priv) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(priv), nil
	}
	return nil, errors.New("unrecognized dkim private key encoding")
}
