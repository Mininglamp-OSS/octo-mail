-- ---------------------------------------------------------------------------
-- Inbound anti-abuse: greylisting + per-recipient sender reputation.
-- ---------------------------------------------------------------------------

-- Greylist triplets: a first-seen (account, sender-domain, client-IP-subnet) is
-- deferred (4xx) until first_seen + delay; once it retries after the delay it is
-- allowed and remembered, so legitimate MTAs (which retry) pass and spam bots
-- (which usually don't) are blocked. Mirrors classic greylisting.
CREATE TABLE IF NOT EXISTS greylist (
    account_id    bigint NOT NULL,
    sender_domain text NOT NULL,
    client_subnet text NOT NULL,                    -- /24 (v4) or /64 (v6)
    first_seen    timestamptz NOT NULL DEFAULT now(),
    allowed_at    timestamptz,                      -- set when it passes the delay
    count         bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (account_id, sender_domain, client_subnet)
);

-- Inbound sender reputation per (recipient account, sender domain): how many
-- messages from this sender the account has accepted (ham) vs marked junk. Used
-- to let known-good senders bypass content thresholds and to reject known-bad.
CREATE TABLE IF NOT EXISTS inbound_reputation (
    account_id    bigint NOT NULL,
    sender_domain text NOT NULL,
    ham_count     bigint NOT NULL DEFAULT 0,
    junk_count    bigint NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, sender_domain)
);

-- DMARC aggregate source: one row per (from-domain, source-IP, SPF result, DKIM
-- result, disposition) with a count, accumulated as we receive mail. This is the
-- raw material for the aggregate reports we (as receiver) send back to sending
-- domains' rua= addresses. rua is the reporting address discovered from the
-- domain's DMARC record.
CREATE TABLE IF NOT EXISTS dmarc_agg (
    id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    from_domain   text NOT NULL,
    rua           text NOT NULL DEFAULT '',
    source_ip     text NOT NULL,
    spf_result    text NOT NULL,                   -- pass/fail/none/...
    dkim_result   text NOT NULL,
    disposition   text NOT NULL,                   -- none/quarantine/reject
    count         bigint NOT NULL DEFAULT 0,
    day           date NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
    reported      boolean NOT NULL DEFAULT false,
    UNIQUE (from_domain, source_ip, spf_result, dkim_result, disposition, day)
);
CREATE INDEX IF NOT EXISTS dmarc_agg_unreported_idx ON dmarc_agg (from_domain, day) WHERE NOT reported;


