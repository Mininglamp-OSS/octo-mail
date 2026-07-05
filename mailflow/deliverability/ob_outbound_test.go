package deliverability_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

const dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	// Ensure schema for the tables we touch.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS suppressions (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, account_id bigint NOT NULL, address text NOT NULL, reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE (account_id, address))`,
		`CREATE TABLE IF NOT EXISTS webhook_events (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, account_id bigint NOT NULL, url text NOT NULL, event text NOT NULL, payload jsonb NOT NULL, attempts int NOT NULL DEFAULT 0, max_attempts int NOT NULL DEFAULT 10, next_attempt timestamptz NOT NULL DEFAULT now(), leased_by text, lease_until timestamptz, delivered boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now())`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	pool.Exec(ctx, `TRUNCATE suppressions, webhook_events RESTART IDENTITY`)
	pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`)
	pool.Exec(ctx, `INSERT INTO tenants (name) VALUES ('t')`)
	return pool
}

// TestSuppressionBlocksSend proves the suppression list stops sending to a
// hard-bounced/complained recipient, and canonicalizes +tag/case.
func TestSuppressionBlocksSend(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	defer pool.Close()
	sup := &deliverability.Suppressions{Pool: pool}

	const tenant, acc = int64(1), int64(1)
	if ok, _ := sup.Suppressed(ctx, acc, "Bob@Remote.Example"); ok {
		t.Fatal("unexpectedly suppressed before add")
	}
	if err := sup.Add(ctx, tenant, acc, "bob@remote.example", "hard bounce"); err != nil {
		t.Fatal(err)
	}
	// Case + "+tag" variants canonicalize to the same base → suppressed.
	for _, v := range []string{"bob@remote.example", "Bob@Remote.Example", "bob+newsletter@remote.example"} {
		ok, err := sup.Suppressed(ctx, acc, v)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("address %q not suppressed (canonicalization failed)", v)
		}
	}
	// A different account is unaffected (per-account).
	if ok, _ := sup.Suppressed(ctx, int64(2), "bob@remote.example"); ok {
		t.Fatal("suppression leaked across accounts")
	}
	// Removal works.
	if err := sup.Remove(ctx, acc, "bob@remote.example"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sup.Suppressed(ctx, acc, "bob@remote.example"); ok {
		t.Fatal("still suppressed after remove")
	}
	t.Logf("OK: suppression add/canonicalize(+tag,case)/per-account isolation/remove")
}

// TestWebhookEnqueue proves delivery/bounce events are queued for HTTP delivery.
func TestWebhookEnqueue(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	defer pool.Close()
	wh := &deliverability.Webhooks{Pool: pool}

	if err := wh.Enqueue(ctx, 1, 1, "https://hook.example/cb", "delivered",
		map[string]any{"rcpt": "bob@remote.example", "msgid": 42}); err != nil {
		t.Fatal(err)
	}
	var n int
	var event, url string
	pool.QueryRow(ctx, `SELECT count(*) FROM webhook_events`).Scan(&n)
	pool.QueryRow(ctx, `SELECT event, url FROM webhook_events LIMIT 1`).Scan(&event, &url)
	if n != 1 || event != "delivered" || url != "https://hook.example/cb" {
		t.Fatalf("webhook not enqueued correctly: n=%d event=%q url=%q", n, event, url)
	}
	t.Logf("OK: webhook event queued (event=%s url=%s)", event, url)
}

// TestMTASTSEnforceRequiresTLS proves the MTA-STS-aware policy: a domain that
// publishes an MTA-STS DNS record yields a TLS-required mode, while a domain
// without one yields opportunistic.
func TestMTASTSEnforceRequiresTLS(t *testing.T) {
	ctx := context.Background()
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			// enforce.example opts into MTA-STS via the _mta-sts TXT record.
			"_mta-sts.enforce.example.": {"v=STSv1; id=20260101000000"},
		},
		AllAuthentic: true,
	}
	p := &deliverability.TLSPolicy{Resolver: resolver}

	// Domain WITH an MTA-STS record → TLS required (policy body unreachable in
	// test, so we fall back to strict).
	mode, enforce, err := p.ModeFor(ctx, "enforce.example")
	if err != nil {
		t.Fatal(err)
	}
	if mode != smtpclient.TLSRequiredStartTLS || !enforce {
		t.Fatalf("MTA-STS domain got mode=%q enforce=%v, want required/true", mode, enforce)
	}

	// Domain WITHOUT an MTA-STS record → opportunistic.
	mode2, enforce2, err := p.ModeFor(ctx, "plain.example")
	if err != nil {
		t.Fatal(err)
	}
	if mode2 != smtpclient.TLSOpportunistic || enforce2 {
		t.Fatalf("non-MTA-STS domain got mode=%q enforce=%v, want opportunistic/false", mode2, enforce2)
	}
	t.Logf("OK: MTA-STS record → TLS required; no record → opportunistic")
}
