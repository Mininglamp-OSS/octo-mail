-- ---------------------------------------------------------------------------
-- Change-log (the spine)
-- ---------------------------------------------------------------------------

-- The change-log is hash-partitioned by account_id: the spine shards cleanly
-- because its PK (account_id, seq) already leads with the shard key, so no query
-- changes — account-scoped reads/writes prune to one partition automatically.
-- This is the open-source equivalent of Citus distribution on account_id; the
-- same key that carries tenant/account isolation everywhere also carries the
-- shard. To scale out, add partitions (or move them to separate tablespaces /
-- Citus worker nodes) — the kernel and protocol code are untouched.
CREATE TABLE IF NOT EXISTS changelog (
    account_id bigint NOT NULL REFERENCES accounts(id),
    seq        bigint NOT NULL,                     -- == IMAP MODSEQ == JMAP state
    kind       smallint NOT NULL,
    mailbox_id bigint,                              -- denormalized for per-mailbox replay
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, seq)
) PARTITION BY HASH (account_id);
-- Default partition count. More/other partitions can be added without code changes.
CREATE TABLE IF NOT EXISTS changelog_p0 PARTITION OF changelog FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS changelog_p1 PARTITION OF changelog FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS changelog_p2 PARTITION OF changelog FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS changelog_p3 PARTITION OF changelog FOR VALUES WITH (MODULUS 4, REMAINDER 3);
CREATE INDEX IF NOT EXISTS changelog_mailbox_idx
    ON changelog (account_id, mailbox_id, seq);     -- CONDSTORE CHANGEDSINCE per mailbox

