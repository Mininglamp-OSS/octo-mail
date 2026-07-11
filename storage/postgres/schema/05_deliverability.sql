
-- ---------------------------------------------------------------------------
-- Deliverability (operator-grade): per-tenant IP pools, DKIM, reputation
-- isolation. Invariant: one spammy tenant must not poison another tenant's or
-- the platform's IP reputation. Reputation is attributed per (tenant, remote
-- domain, ip) and the send gate reads it per tenant, so throttling A never
-- touches B.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ip_pools (
    id      bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name    text NOT NULL UNIQUE,
    purpose text NOT NULL DEFAULT 'shared'        -- shared | dedicated | warmup | penalty
);

CREATE TABLE IF NOT EXISTS ip_addresses (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    pool_id      bigint NOT NULL REFERENCES ip_pools(id),
    ip           inet NOT NULL,
    ptr          text,
    warmup_stage int NOT NULL DEFAULT 0,
    daily_cap    bigint NOT NULL DEFAULT 0,        -- 0 = uncapped
    sent_today   bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tenant_ip_assignment (
    tenant_id bigint NOT NULL REFERENCES tenants(id),
    pool_id   bigint NOT NULL REFERENCES ip_pools(id),
    dedicated boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, pool_id)
);

CREATE TABLE IF NOT EXISTS dkim_keys (
    id          bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id   bigint NOT NULL REFERENCES tenants(id),
    domain      text NOT NULL,
    selector    text NOT NULL,
    algo        text NOT NULL DEFAULT 'ed25519',
    private_key bytea NOT NULL,
    active      boolean NOT NULL DEFAULT true,
    UNIQUE (tenant_id, domain, selector)
);

-- Raw reputation events (bounce/complaint/delivered/deferral), attributed to the
-- sending tenant via VERP return-path decoding.
CREATE TABLE IF NOT EXISTS reputation_events (
    id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id     bigint NOT NULL REFERENCES tenants(id),
    account_id    bigint,
    kind          smallint NOT NULL,               -- 0 delivered,1 bounce,2 complaint,3 deferral
    remote_domain text NOT NULL,
    ip_id         bigint,
    at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reputation_events_scope_idx
    ON reputation_events (tenant_id, remote_domain, at);

-- msg_id ties a reputation event to the originating outbound message (the signed
-- VERP token's msgID) so inbound bounce/complaint ingest is idempotent: a report
-- delivered/replayed N times for the same (tenant, msg_id) records at most one
-- event. Without this, an attacker who observes a victim's in-the-clear signed
-- VERP bounce address could replay it to drive the victim to auto-pause (a
-- cross-tenant reputation DoS via replay rather than forgery). NULL for events
-- with no single originating message (delivery-time bounces), which are not
-- deduped.
ALTER TABLE reputation_events ADD COLUMN IF NOT EXISTS msg_id bigint;
CREATE UNIQUE INDEX IF NOT EXISTS reputation_events_tenant_msg_uniq
    ON reputation_events (tenant_id, msg_id) WHERE msg_id IS NOT NULL;

-- Rolled-up per (tenant, remote domain) reputation the send gate consults.
CREATE TABLE IF NOT EXISTS reputation_score (
    tenant_id      bigint NOT NULL REFERENCES tenants(id),
    remote_domain  text NOT NULL,
    sent           bigint NOT NULL DEFAULT 0,
    complaints     bigint NOT NULL DEFAULT 0,
    bounces        bigint NOT NULL DEFAULT 0,
    paused         boolean NOT NULL DEFAULT false, -- tenant throttled for this domain
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, remote_domain)
);
-- paused_at records when paused last flipped true, so the auto-unpause job can
-- require a minimum pause dwell and the admin can report pause age. NULL when not
-- paused. Additive for existing databases.
ALTER TABLE reputation_score ADD COLUMN IF NOT EXISTS paused_at timestamptz;

-- Per-day reputation rollup: bounded-cardinality time buckets (one row per
-- tenant/remote-domain/UTC-day) that make a SLIDING-WINDOW rate cheap and exact,
-- without a per-delivered-message event row (which would be write-amplifying at
-- mail volume). The pause/unpause decision sums the buckets whose day falls in
-- the window (default 7d). reputation_score stays as the lifetime total + the
-- pause flag the hot send-gate reads.
CREATE TABLE IF NOT EXISTS reputation_daily (
    tenant_id     bigint NOT NULL REFERENCES tenants(id),
    remote_domain text NOT NULL,
    day           date NOT NULL,                       -- UTC day bucket
    sent          bigint NOT NULL DEFAULT 0,
    bounces       bigint NOT NULL DEFAULT 0,
    complaints    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, remote_domain, day)
);
CREATE INDEX IF NOT EXISTS reputation_daily_scope_idx
    ON reputation_daily (tenant_id, remote_domain, day);

-- Suppression list: recipient addresses we must stop sending to (hard bounces,
-- complaints). Per (tenant, account) so one tenant's suppression never blocks
-- another's mail. Checked before every outbound send.
CREATE TABLE IF NOT EXISTS suppressions (
    id         bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id  bigint NOT NULL REFERENCES tenants(id),
    account_id bigint NOT NULL,
    address    text NOT NULL,                       -- base (canonicalized) recipient
    reason     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, address)
);

-- Outbound webhook events: delivery/bounce/complaint notifications queued for
-- HTTP delivery to the tenant's configured endpoint. Consumed by a webhook
-- worker (lease pattern like the mail queue).
CREATE TABLE IF NOT EXISTS webhook_events (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id    bigint NOT NULL REFERENCES tenants(id),
    account_id   bigint NOT NULL,
    url          text NOT NULL,
    event        text NOT NULL,                     -- delivered | bounced | complaint
    payload      jsonb NOT NULL,
    attempts     int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 10,
    next_attempt timestamptz NOT NULL DEFAULT now(),
    leased_by    text,
    lease_until  timestamptz,
    delivered    boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_due_idx ON webhook_events (next_attempt)
    WHERE leased_by IS NULL AND NOT delivered;

-- Aggregate report ingestion (DMARC RUA + TLS-RPT). Reports arrive as email
-- attachments at the report addresses; parsed and stored for the domain owner.
CREATE TABLE IF NOT EXISTS dmarc_reports (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    domain       text NOT NULL,                     -- policy-published domain
    org_name     text NOT NULL,                     -- reporting org
    report_id    text NOT NULL,
    date_begin   timestamptz,
    date_end     timestamptz,
    pass_count   bigint NOT NULL DEFAULT 0,         -- rows where dmarc passed
    fail_count   bigint NOT NULL DEFAULT 0,
    received_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_name, report_id)
);
CREATE INDEX IF NOT EXISTS dmarc_reports_domain_idx ON dmarc_reports (domain, date_begin);

CREATE TABLE IF NOT EXISTS tlsrpt_reports (
    id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    domain        text NOT NULL,
    org_name      text NOT NULL,
    report_id     text NOT NULL,
    success_count bigint NOT NULL DEFAULT 0,
    failure_count bigint NOT NULL DEFAULT 0,
    received_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_name, report_id)
);
CREATE INDEX IF NOT EXISTS tlsrpt_reports_domain_idx ON tlsrpt_reports (domain);

-- Per-tenant outbound send-rate limiter: a fixed-window counter (one row per
-- tenant per window start) enforced on EVERY send regardless of the egress-IP
-- pool. Warmup/per-IP daily caps only exist when the egress pool is enabled; this
-- gives a baseline platform-wide throttle so a single tenant burst can't dominate
-- outbound capacity (or a shared IP's reputation) even in the no-egress-pool
-- default. The limiter increments count on each send attempt and blocks (defers)
-- once count exceeds the configured cap for the current window. Elapsed-window
-- rows are pruned by Service.PruneSendRate, run on the reputation-unpause cluster
-- singleton's tick (which runs regardless of the egress pool), so the table stays
-- bounded to roughly one row per active tenant.
CREATE TABLE IF NOT EXISTS tenant_send_rate (
    tenant_id    bigint NOT NULL REFERENCES tenants(id),
    window_start timestamptz NOT NULL,               -- start of the fixed window (UTC)
    count        bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, window_start)
);

-- Marker for once-per-day cluster-singleton maintenance (IP warmup advance +
-- daily-counter reset). A single row; the leader's periodic tick only acts when
-- the stored date is behind today's UTC date, so it runs exactly once per day
-- regardless of tick frequency or which node is leader after a failover.
CREATE TABLE IF NOT EXISTS maintenance_marker (
    name     text PRIMARY KEY,
    last_run date NOT NULL
);
