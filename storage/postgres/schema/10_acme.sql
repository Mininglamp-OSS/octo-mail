
-- ---------------------------------------------------------------------------
-- Shared ACME cache: leader-gated cluster certificate issuance (issue #32)
-- ---------------------------------------------------------------------------
-- Built-in ACME (autocert) keeps the account key, issued certs, and tls-alpn-01
-- challenge token certs in an autocert.Cache. The node-local DirCache made ACME
-- single-node only (H17): each node registered its own account and raced to order
-- the same certs, and a tls-alpn-01 challenge could land on a node that didn't
-- create the order. Backing autocert.Cache with THIS table makes the whole
-- stateless cluster share one account key + cert set: the leader orders and writes
-- here, followers serve certs (and answer challenges) from here, so any node's :443
-- can complete a validation the leader started.
--
-- name is the autocert cache key: "<domain>" (ECDSA keycert), "<domain>+rsa"
-- (legacy-client keycert), "<domain>+token" (tls-alpn-01 challenge cert), and
-- "acme_account+key" (the shared ACME account identity key). data is the raw
-- PEM/DER autocert blob. Mirrors the bytea (dkim_keys) + name-PK (maintenance_marker)
-- precedents in 05_deliverability.sql.
CREATE TABLE IF NOT EXISTS acme_cache (
    name       text PRIMARY KEY,
    data       bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
