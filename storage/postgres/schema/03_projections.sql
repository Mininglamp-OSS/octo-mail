-- ---------------------------------------------------------------------------
-- Projections (derived, rebuildable folds of the log)
-- ---------------------------------------------------------------------------

-- mailboxes and messages are hash-partitioned by account_id too — the same
-- shard key as the changelog spine. The identity sequence on `id` is global
-- (shared across partitions), so ids remain unique and bare-id lookups still
-- resolve; adding account_id to a lookup lets Postgres prune to one partition.
-- PKs and unique constraints must include the partition key (account_id); the
-- messages→mailboxes FK is therefore composite.
CREATE TABLE IF NOT EXISTS mailboxes (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    account_id  bigint NOT NULL REFERENCES accounts(id),
    parent_id   bigint,
    name        text NOT NULL,
    uidvalidity bigint NOT NULL,
    uidnext     bigint NOT NULL DEFAULT 1,          -- per-mailbox UID allocator
    createseq   bigint NOT NULL,
    modseq      bigint NOT NULL,
    expunged    boolean NOT NULL DEFAULT false,
    su_archive  boolean NOT NULL DEFAULT false,
    su_draft    boolean NOT NULL DEFAULT false,
    su_junk     boolean NOT NULL DEFAULT false,
    su_sent     boolean NOT NULL DEFAULT false,
    su_trash    boolean NOT NULL DEFAULT false,
    subscribed  boolean NOT NULL DEFAULT false,     -- IMAP SUBSCRIBE state (LIST-EXTENDED)
    keywords    text[] NOT NULL DEFAULT '{}',
    c_total     bigint NOT NULL DEFAULT 0,
    c_deleted   bigint NOT NULL DEFAULT 0,
    c_unread    bigint NOT NULL DEFAULT 0,
    c_unseen    bigint NOT NULL DEFAULT 0,
    c_size      bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, id)
) PARTITION BY HASH (account_id);
CREATE TABLE IF NOT EXISTS mailboxes_p0 PARTITION OF mailboxes FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS mailboxes_p1 PARTITION OF mailboxes FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS mailboxes_p2 PARTITION OF mailboxes FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS mailboxes_p3 PARTITION OF mailboxes FOR VALUES WITH (MODULUS 4, REMAINDER 3);
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_name_idx
    ON mailboxes (account_id, name) WHERE NOT expunged;

CREATE TABLE IF NOT EXISTS messages (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    account_id  bigint NOT NULL REFERENCES accounts(id),
    mailbox_id  bigint NOT NULL,
    uid         bigint NOT NULL,
    createseq   bigint NOT NULL,
    modseq      bigint NOT NULL,
    expunged    boolean NOT NULL DEFAULT false,
    f_seen      boolean NOT NULL DEFAULT false,
    f_answered  boolean NOT NULL DEFAULT false,
    f_flagged   boolean NOT NULL DEFAULT false,
    f_forwarded boolean NOT NULL DEFAULT false,
    f_junk      boolean NOT NULL DEFAULT false,
    f_notjunk   boolean NOT NULL DEFAULT false,
    f_deleted   boolean NOT NULL DEFAULT false,
    f_draft     boolean NOT NULL DEFAULT false,
    f_phishing  boolean NOT NULL DEFAULT false,
    f_mdnsent   boolean NOT NULL DEFAULT false,
    keywords    text[] NOT NULL DEFAULT '{}',
    blob_ref    text NOT NULL,
    size        bigint NOT NULL,
    thread_id   bigint,
    email_id    bigint,                             -- JMAP email identity: groups sibling rows (same content, multiple mailboxes); NULL = row is its own email (effective id = id)
    received_at timestamptz NOT NULL DEFAULT now(),  -- IMAP INTERNALDATE
    save_date   timestamptz NOT NULL DEFAULT now(),  -- IMAP SAVEDATE (RFC 8514): when the row entered this mailbox
    msg_prefix  bytea NOT NULL DEFAULT '',          -- generated headers, prepended on read
    envelope    jsonb,                              -- parsed MIME cache
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, mailbox_id, uid),
    FOREIGN KEY (account_id, mailbox_id) REFERENCES mailboxes (account_id, id)
) PARTITION BY HASH (account_id);
CREATE TABLE IF NOT EXISTS messages_p0 PARTITION OF messages FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS messages_p1 PARTITION OF messages FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS messages_p2 PARTITION OF messages FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS messages_p3 PARTITION OF messages FOR VALUES WITH (MODULUS 4, REMAINDER 3);
CREATE INDEX IF NOT EXISTS messages_modseq_idx ON messages (account_id, mailbox_id, modseq);
CREATE INDEX IF NOT EXISTS messages_thread_idx ON messages (account_id, thread_id);
CREATE INDEX IF NOT EXISTS messages_email_idx ON messages (account_id, email_id);

-- H13: denormalized list-summary columns so list/query paths don't MIME-parse
-- every message body per request. Populated asynchronously by the threading
-- projection fold (which already opens+parses each message), backfilled by a
-- projection rebuild. summary_folded distinguishes "folded, genuinely empty"
-- from "not yet folded" so list endpoints fall back to an on-the-fly parse only
-- for the (rare, recent) unfolded rows. ADD COLUMN cascades to the hash
-- partitions.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS subject        text NOT NULL DEFAULT '';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS from_addr      text NOT NULL DEFAULT ''; -- display: bare sender address
ALTER TABLE messages ADD COLUMN IF NOT EXISTS to_addrs       text NOT NULL DEFAULT ''; -- display: space-joined recipient addresses
ALTER TABLE messages ADD COLUMN IF NOT EXISTS from_search    text NOT NULL DEFAULT ''; -- filter: sender name + address, substring-searchable
ALTER TABLE messages ADD COLUMN IF NOT EXISTS to_search      text NOT NULL DEFAULT ''; -- filter: recipient names + addresses
ALTER TABLE messages ADD COLUMN IF NOT EXISTS preview        text NOT NULL DEFAULT '';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS summary_folded boolean NOT NULL DEFAULT false;
-- Received-desc list ordering + email-group dedup (DISTINCT ON) are the hot
-- list/query access pattern; back them with an index.
CREATE INDEX IF NOT EXISTS messages_received_idx ON messages (account_id, received_at DESC, id DESC);

-- IMAP METADATA (RFC 5464): per-mailbox and server (mailbox_id=0) annotations.
CREATE TABLE IF NOT EXISTS annotations (
    account_id bigint NOT NULL REFERENCES accounts(id),
    mailbox_id bigint NOT NULL,                      -- 0 = server-level entry ("" mailbox)
    key        text NOT NULL,                        -- e.g. /private/comment, /shared/vendor/token
    value      bytea,                                -- NULL = entry absent (removal); else the value
    is_string  boolean NOT NULL DEFAULT true,
    PRIMARY KEY (account_id, mailbox_id, key)
);

-- URLAUTH (RFC 4467) per-mailbox access keys: the secret keyed into the HMAC
-- that authorizes an IMAP URL. Rotating a key (RESETKEY) revokes every URL
-- previously authorized against that mailbox. Kept in Postgres so any stateless
-- node validates URLFETCH consistently.
CREATE TABLE IF NOT EXISTS urlauth_keys (
    account_id bigint NOT NULL REFERENCES accounts(id),
    mailbox_id bigint NOT NULL,
    key        bytea NOT NULL,
    PRIMARY KEY (account_id, mailbox_id)
);

-- Per-account delivery rulesets (per-account delivery rules): a header
-- substring match forces delivery to a named mailbox and may accept unconditionally.
CREATE TABLE IF NOT EXISTS rulesets (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    account_id   bigint NOT NULL REFERENCES accounts(id),
    header_name  text NOT NULL,                       -- e.g. From, List-Id, X-Mailing-List
    header_substr text NOT NULL,                      -- case-insensitive substring to match
    mailbox      text NOT NULL,                        -- destination mailbox (created if absent)
    force_accept boolean NOT NULL DEFAULT true,        -- bypass reputation/content rejection
    is_forward   boolean NOT NULL DEFAULT false,       -- message is forwarded: relax DMARC/content
    ord          int NOT NULL DEFAULT 0                -- lower = evaluated first
);
CREATE INDEX IF NOT EXISTS rulesets_account_idx ON rulesets (account_id, ord);

-- JMAP VacationResponse (RFC 8621 §8): at most one per account (singleton id).
CREATE TABLE IF NOT EXISTS vacation_response (
    account_id  bigint PRIMARY KEY REFERENCES accounts(id),
    enabled     boolean NOT NULL DEFAULT false,
    subject     text NOT NULL DEFAULT '',
    text_body   text NOT NULL DEFAULT '',
    html_body   text NOT NULL DEFAULT '',
    from_date   timestamptz,
    to_date     timestamptz
);

-- Dedup log so a vacation auto-reply is sent at most once per sender per window.
CREATE TABLE IF NOT EXISTS vacation_sent (
    account_id bigint NOT NULL REFERENCES accounts(id),
    recipient  text NOT NULL,                        -- the original sender we replied to
    sent_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, recipient)
);

CREATE TABLE IF NOT EXISTS blobs (
    hash      text NOT NULL,
    tenant_id bigint NOT NULL REFERENCES tenants(id),
    size      bigint NOT NULL,
    refcount  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hash)                   -- dedup scoped within tenant
);

CREATE TABLE IF NOT EXISTS quota_counters (
    scope_type smallint NOT NULL,                   -- 0=tenant, 1=account
    scope_id   bigint NOT NULL,
    bytes_used bigint NOT NULL DEFAULT 0,
    msg_count  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_type, scope_id)
);

-- Full-text search projection (async, tolerant): a tsvector per message folded
-- from the message body/headers by a worker tailing the changelog. It is NOT
-- updated in the delivery transaction — read-your-write is not required for
-- search — so delivery latency is unaffected. Rebuildable from the log.
CREATE TABLE IF NOT EXISTS fts (
    account_id bigint NOT NULL,
    message_id bigint NOT NULL,
    tsv        tsvector NOT NULL,
    PRIMARY KEY (account_id, message_id)
);
CREATE INDEX IF NOT EXISTS fts_tsv_idx ON fts USING gin (tsv);

-- Projection cursors: high-water mark (last folded changelog seq) per async
-- projection per account. Adding a new projection = insert a cursor at 0 and let
-- the worker fold the whole log up to the live head, then stay live — no lock,
-- no downtime.
CREATE TABLE IF NOT EXISTS projection_cursor (
    account_id bigint NOT NULL,
    name       text NOT NULL,                       -- e.g. 'fts', 'threads'
    seq        bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, name)
);

-- Threading projection index: each message's canonical reference ids
-- (Message-ID, In-Reply-To, References). The thread worker matches a new
-- message's refs against prior messages' refs to join conversations. Derived
-- from the log; cleared and re-folded on rebuild.
CREATE TABLE IF NOT EXISTS thread_refs (
    account_id bigint NOT NULL,
    message_id bigint NOT NULL,
    ref        text NOT NULL,
    PRIMARY KEY (account_id, message_id, ref)
);
CREATE INDEX IF NOT EXISTS thread_refs_ref_idx ON thread_refs (account_id, ref);

