-- ---------------------------------------------------------------------------
-- Junk (bayesian spam) filter — shared per-account word statistics
-- ---------------------------------------------------------------------------
-- The junk filter is per-account bayesian: marking a message \Junk trains spam,
-- moving it out trains ham, and classification scores incoming mail from those
-- learned word frequencies. This state MUST be shared across nodes — otherwise
-- training on one node has no effect on another's verdicts, and every node keeps
-- a divergent local filter (the stateless-node model broken). So the counts live
-- in PostgreSQL, not in per-node files.
--
-- junk_words holds, per (account, token), how many trained ham and spam messages
-- contained that token. junk_totals holds the per-account trained ham/spam
-- message counts (the denominators). The bayesian score for a token is
-- (spam/spams) / (spam/spams + ham/hams), combined over the most significant
-- tokens — see junkfilter.Manager.
CREATE TABLE IF NOT EXISTS junk_words (
    account_id bigint NOT NULL,
    word       text   NOT NULL,
    ham        bigint NOT NULL DEFAULT 0,
    spam       bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, word)
);

CREATE TABLE IF NOT EXISTS junk_totals (
    account_id bigint NOT NULL PRIMARY KEY,
    hams       bigint NOT NULL DEFAULT 0,
    spams      bigint NOT NULL DEFAULT 0
);
