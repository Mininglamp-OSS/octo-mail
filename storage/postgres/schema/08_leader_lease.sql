-- ---------------------------------------------------------------------------
-- Leader lease: cross-promotion fencing for the single-active-leader primitive
-- ---------------------------------------------------------------------------

-- The ha.Leader election uses a session-level pg_advisory_lock for fast
-- same-primary mutual exclusion (the two-key form pg_advisory_lock(classid,
-- objid) under a dedicated leader classid, so leader keys can never alias the
-- one-key per-account write locks or the schema-bootstrap lock — see
-- ops/ha.lockClassLeader). But an advisory lock is primary-LOCAL and NOT
-- replicated: after a PostgreSQL failover the old primary and the promoted
-- replica have independent lock namespaces, so the lock alone cannot tell a
-- demoted old primary from the new one. This lease row is ordinary table data —
-- it lives in the WAL and is therefore visible identically on both — and carries
-- an `epoch` bumped on every acquisition. It fences the promotion case
-- two ways: the heartbeat is a WRITE (so a leader whose primary was demoted to a
-- read-only replica fails its next renew and steps down), and the epoch is a
-- fencing token that non-idempotent leader work stamps onto its writes so a stale
-- old leader's in-flight write is rejected. `heartbeat_at` also gives operators a
-- last-seen-leader timestamp.
--
-- Fencing is by (holder, epoch) IDENTITY, not epoch ordering: a clean Resign
-- deletes the row, so the next acquisition re-inserts at epoch 1. That is safe —
-- checks compare the exact pair on the live leadership connection, and distinct
-- nodes carry distinct holders — so the epoch need not be globally monotonic,
-- only distinct-per-live-tenure.
--
-- Mirrors the lease idiom already used for the outbound queue
-- (queue.leased_by/lease_until, 04_queue.sql) and daily maintenance
-- (maintenance_marker, 05_deliverability.sql).
CREATE TABLE IF NOT EXISTS leader_lease (
    key          bigint PRIMARY KEY,   -- the advisory-lock key this lease fences
    holder       text NOT NULL,        -- node id of the current leader
    epoch        bigint NOT NULL,      -- fencing token, bumped on each acquisition (distinct per tenure)
    heartbeat_at timestamptz NOT NULL  -- last renew; operator visibility + read-only-demotion probe
);
