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
-- Mirrors the bytea secret storage of dkim_keys (05_deliverability.sql) and the
-- name-keyed singleton idiom of maintenance_marker (05) / leader_lease (08).
CREATE TABLE IF NOT EXISTS acme_cache (
    name       text PRIMARY KEY,                       -- storage key (see scheme above)
    data       bytea NOT NULL,                         -- PEM bundle or raw key material
    updated_at timestamptz NOT NULL DEFAULT now()      -- change marker: lets followers detect leader renewals
);
