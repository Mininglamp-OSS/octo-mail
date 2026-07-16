-- ---------------------------------------------------------------------------
-- ACME cache: shared storage for cluster-wide (leader-gated) ACME issuance
-- ---------------------------------------------------------------------------

-- octo-mail's built-in ACME can run across the stateless cluster when a DNS-01
-- solver is configured: exactly one node (the leader, elected via ops/ha) runs
-- the ACME order/renewal flow and writes the issued certificates here; every
-- node serves TLS by reading certificates from this shared table. This removes
-- the node-local cert cache that made built-in ACME single-node only (H17/#32).
--
-- Unlike most octo-mail tables this is NOT partitioned by account_id: the ACME
-- account key and issued certificates are cluster identity, not tenant data, so
-- there is a single small key/value space shared by all nodes.
--
-- Stored values (name = key):
--   acct-key:<sha256(directoryURL)>  ACME account private key (PKCS#8 PEM)
--   cert:<host>                      PEM bundle: PRIVATE KEY block + CERTIFICATE chain
-- (The ACME account URL/KID is not persisted: x/crypto/acme re-derives and caches
-- it in-process from the account key on each leader's first registration.)
--
-- Secrets at rest: when OCTO_MAIL_KEY_SECRET is set, the `data` values are
-- AES-256-GCM encrypted by the same deliverability.KeyCipher used for
-- dkim_keys.private_key (05_deliverability.sql), with the cache key bound as AAD;
-- otherwise they are plaintext (an explicit, startup-logged operator choice). The
-- column type mirrors dkim_keys (bytea); the encryption is applied in
-- security/acme, not by this DDL. Rotating OCTO_MAIL_KEY_SECRET is a hard cutover
-- (no plaintext downgrade): existing rows become unreadable, so DELETE FROM
-- acme_cache after a rotation to force re-issuance under the new secret.
--
-- Follows the name-keyed singleton idiom of maintenance_marker (05) / leader_lease
-- (08), and (with OCTO_MAIL_KEY_SECRET) the encrypted-bytea-secret storage of
-- dkim_keys (05_deliverability.sql).
CREATE TABLE IF NOT EXISTS acme_cache (
    name       text PRIMARY KEY,                       -- storage key (see scheme above)
    data       bytea NOT NULL,                         -- PEM bundle or raw key material
    updated_at timestamptz NOT NULL DEFAULT now()      -- change marker: lets followers detect leader renewals
);
