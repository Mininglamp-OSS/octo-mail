-- octo-mail schema: per-account API keys (agent-facing Bearer auth).
--
-- An API key is an account-scoped bearer credential: presenting it on the JMAP
-- or WebAPI HTTP surface is equivalent to that account's login. The raw key is
-- never stored — only a hash of its secret half (see security/auth). Tokens have
-- the form omk_<key_prefix>_<secret>: key_prefix is an indexed lookup selector,
-- the secret is constant-time verified against cred.
--
-- Scope is deliberately per-account (not per-tenant): an agent holding a key can
-- reach only its own mailbox, matching octo-mail's structural tenant isolation.

CREATE TABLE IF NOT EXISTS api_keys (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id    bigint NOT NULL REFERENCES tenants(id),
    account_id   bigint NOT NULL REFERENCES accounts(id),
    login        text NOT NULL,                 -- the principal login the key acts as
    name         text NOT NULL,                 -- human label
    key_prefix   text NOT NULL,                 -- lookup selector (public half)
    cred         jsonb NOT NULL,                -- hash of the secret half
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

-- Lookup by prefix, only among live (non-revoked) keys.
CREATE INDEX IF NOT EXISTS api_keys_prefix ON api_keys(key_prefix) WHERE revoked_at IS NULL;
