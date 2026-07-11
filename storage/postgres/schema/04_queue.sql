-- ---------------------------------------------------------------------------
-- Outbound delivery queue (shared; no node owns it)
-- ---------------------------------------------------------------------------
-- The outbound queue follows the same spine pattern as the rest of octo-mail: an
-- append-only LOG is the source of truth, and a mutable PROJECTION serves the
-- hot due-scan. queue_log records every lifecycle fact (enqueued/attempt/
-- delivered/failed/dropped/held/...); the queue table is the folded current
-- state, updated in the SAME transaction as the log append. History, per-attempt
-- results, and retired messages are all just views over the log — there is no
-- separate results/retired table to keep in sync.
--
-- Unlike the per-account changelog, the queue is a cross-account work pool with
-- no single-account home, so its log is a standalone shared log (not partitioned
-- by account). Coordination of "who delivers now" is a time-bounded lease
-- (leased_by/lease_until + FOR UPDATE SKIP LOCKED): the log carries the facts,
-- the lease carries the exclusive right to perform the external SMTP side effect.
-- A crashed node's lease expires and the work is reclaimed.

-- The mutable projection: the current schedulable state of each queued message.
CREATE TABLE IF NOT EXISTS queue (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id    bigint NOT NULL REFERENCES tenants(id),
    account_id   bigint NOT NULL REFERENCES accounts(id),
    mail_from    text NOT NULL,
    rcpt_to      text NOT NULL,
    blob_ref     text NOT NULL,                     -- message body in blob store
    size         bigint NOT NULL,
    attempts     int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 10,
    next_attempt timestamptz NOT NULL DEFAULT now(),
    leased_by    text,                              -- node id holding the lease
    lease_until  timestamptz,
    hold         boolean NOT NULL DEFAULT false,    -- paused: never claimed while true
    last_attempt timestamptz,                       -- time of most recent attempt (projection)
    last_error   text,                              -- error from most recent failed attempt (projection)
    delayed_dsn  boolean NOT NULL DEFAULT false,    -- "still trying" warning DSN already sent (dedup)
    require_tls  boolean,                           -- per-message TLS override: NULL=policy, true=force verified, false=allow plaintext
    dsn_notify   text,                              -- RFC 3461 NOTIFY: comma list of NEVER/SUCCESS/FAILURE/DELAY ('' = default)
    dsn_ret      text,                              -- RFC 3461 RET: FULL | HDRS ('' = default, headers only)
    dsn_envid    text,                              -- RFC 3461 ENVID: envelope id echoed in the DSN
    dsn_orcpt    text,                              -- RFC 3461 ORCPT: original recipient echoed in the DSN
    body_8bitmime boolean NOT NULL DEFAULT false,   -- RFC 6152 BODY=8BITMIME requested: re-negotiate on delivery
    smtputf8      boolean NOT NULL DEFAULT false,    -- RFC 6531 SMTPUTF8 requested: re-negotiate on delivery
    created_at   timestamptz NOT NULL DEFAULT now()
);
-- Idempotent column adds for existing databases (dev has no migration baggage,
-- but Open applies the schema on every start, so keep it forward-only).
ALTER TABLE queue ADD COLUMN IF NOT EXISTS hold         boolean NOT NULL DEFAULT false;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS last_attempt timestamptz;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS last_error   text;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS delayed_dsn  boolean NOT NULL DEFAULT false;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS require_tls  boolean;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS dsn_notify   text;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS dsn_ret      text;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS dsn_envid    text;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS dsn_orcpt    text;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS body_8bitmime boolean NOT NULL DEFAULT false;
ALTER TABLE queue ADD COLUMN IF NOT EXISTS smtputf8      boolean NOT NULL DEFAULT false;
-- Due-message scan: unleased, not on hold, attempt time reached.
CREATE INDEX IF NOT EXISTS queue_due_idx ON queue (next_attempt)
    WHERE leased_by IS NULL AND hold = false;

-- The source of truth: an append-only log of every queue lifecycle fact, keyed
-- by the queue message id (stable across the message's life). Current state
-- (the queue table) is the fold of this log; per-attempt history and retired
-- messages are views over it. kind is one of:
--   enqueued | attempt | delivered | failed | dropped | held | unheld |
--   rescheduled | delayed | requiretls | scheduled
-- payload holds kind-specific detail (attempt: {n, duration_ms, success, code,
-- secode, error}). Terminal entries (delivered/failed/dropped) carry keep_until;
-- the retention sweep deletes a message's whole log once that lapses.
CREATE TABLE IF NOT EXISTS queue_log (
    id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    queue_id   bigint NOT NULL,                     -- the queue message this fact is about
    tenant_id  bigint NOT NULL,
    account_id bigint NOT NULL,
    rcpt_to    text NOT NULL DEFAULT '',
    kind       text NOT NULL,
    payload    jsonb NOT NULL DEFAULT '{}',
    keep_until timestamptz,                         -- set on terminal entries; retention horizon
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS queue_log_qid_idx ON queue_log (queue_id, id);
-- Retention sweep + retired listing both key on terminal entries (keep_until set).
CREATE INDEX IF NOT EXISTS queue_log_keep_idx ON queue_log (keep_until) WHERE keep_until IS NOT NULL;

-- Hold rules: auto-hold newly-enqueued (and existing) messages matching criteria.
-- An empty (NULL) criterion is a wildcard; an all-NULL rule matches everything.
-- Mirrors mox's HoldRule: an operator freezes a class of outbound mail (e.g. a
-- compromised account or a domain under investigation) without dropping it.
CREATE TABLE IF NOT EXISTS queue_hold_rules (
    id               bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id        bigint NOT NULL REFERENCES tenants(id),
    account_id       bigint,                         -- NULL = any account in tenant
    sender_domain    text,                           -- NULL = any sender domain
    recipient_domain text,                           -- NULL = any recipient domain
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS queue_hold_rules_tenant_idx ON queue_hold_rules (tenant_id);
