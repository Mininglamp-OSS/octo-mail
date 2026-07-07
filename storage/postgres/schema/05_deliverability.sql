
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

-- Marker for once-per-day cluster-singleton maintenance (IP warmup advance +
-- daily-counter reset). A single row; the leader's periodic tick only acts when
-- the stored date is behind today's UTC date, so it runs exactly once per day
-- regardless of tick frequency or which node is leader after a failover.
CREATE TABLE IF NOT EXISTS maintenance_marker (
    name     text PRIMARY KEY,
    last_run date NOT NULL
);
