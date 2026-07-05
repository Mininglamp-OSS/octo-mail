-- octo-mail schema: change-log-centric mail kernel.
--
-- The changelog is the spine (append-only, per-account, monotonically
-- sequenced). mailboxes/messages/fts/quota are projections folded from it and
-- are rebuildable. A single per-account counter (accounts.changelog_seq) serves
-- both IMAP MODSEQ/CONDSTORE and JMAP state — they are two views of one offset.

-- ---------------------------------------------------------------------------
-- Directory object graph (identity + tenant isolation root)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenants (
    id          bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name        text NOT NULL UNIQUE,
    quota_bytes bigint,
    kms_key_id  text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS principals (
    id        bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id bigint NOT NULL REFERENCES tenants(id),
    login     text NOT NULL,
    cred      jsonb NOT NULL DEFAULT '{}'::jsonb,   -- scram salts / argon2 / tls pubkeys
    UNIQUE (tenant_id, login)
);

CREATE TABLE IF NOT EXISTS accounts (
    id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id     bigint NOT NULL REFERENCES tenants(id),
    principal_id  bigint REFERENCES principals(id),
    name          text NOT NULL,
    quota_bytes   bigint,
    disabled      boolean NOT NULL DEFAULT false,
    -- Log head: the highest assigned change-log seq. Advanced under the
    -- per-account advisory writer lock, in the same tx as the appended entries.
    changelog_seq bigint NOT NULL DEFAULT 0,
    uidvalidity_next bigint NOT NULL DEFAULT 1,      -- next UIDVALIDITY to hand out
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS domains (
    id        bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id bigint NOT NULL REFERENCES tenants(id),
    domain    text NOT NULL UNIQUE,                 -- a domain belongs to exactly one tenant
    disabled  boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS addresses (
    id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id  bigint NOT NULL REFERENCES tenants(id),
    domain_id  bigint NOT NULL REFERENCES domains(id),
    account_id bigint NOT NULL REFERENCES accounts(id),
    localpart  text NOT NULL,
    is_alias   boolean NOT NULL DEFAULT false,
    UNIQUE (domain_id, localpart)
);

