package reportdb_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/ops/reportdb"
	"github.com/jackc/pgx/v5/pgxpool"
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
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS dmarc_reports (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, domain text NOT NULL, org_name text NOT NULL, report_id text NOT NULL, date_begin timestamptz, date_end timestamptz, pass_count bigint NOT NULL DEFAULT 0, fail_count bigint NOT NULL DEFAULT 0, received_at timestamptz NOT NULL DEFAULT now(), UNIQUE (org_name, report_id))`,
		`CREATE TABLE IF NOT EXISTS tlsrpt_reports (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, domain text NOT NULL, org_name text NOT NULL, report_id text NOT NULL, success_count bigint NOT NULL DEFAULT 0, failure_count bigint NOT NULL DEFAULT 0, received_at timestamptz NOT NULL DEFAULT now(), UNIQUE (org_name, report_id))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	pool.Exec(ctx, `TRUNCATE dmarc_reports, tlsrpt_reports RESTART IDENTITY`)
	return pool
}

const dmarcXML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc@google.com</email>
    <report_id>report-12345</report_id>
    <date_range><begin>1782800000</begin><end>1782886400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>acme.example</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row><source_ip>10.0.0.9</source_ip><count>8</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>acme.example</header_from></identifiers>
    <auth_results><spf><domain>acme.example</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.9</source_ip><count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>acme.example</header_from></identifiers>
    <auth_results><spf><domain>evil.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`

const tlsrptJSON = `{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": "2026-06-30T00:00:00Z", "end-datetime": "2026-07-01T00:00:00Z"},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "tls-report-999",
  "policies": [{
    "policy": {"policy-type": "sts", "policy-domain": "acme.example"},
    "summary": {"total-successful-session-count": 100, "total-failure-session-count": 5}
  }]
}`

// TestReportIngest proves WF-E: DMARC aggregate XML and TLS-RPT JSON reports are
// parsed (via the dmarcrpt/tlsrpt) and stored, and per-domain totals are
// queryable. Ingestion is idempotent per (org, report_id).
func TestReportIngest(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	defer pool.Close()
	s := &reportdb.Store{Pool: pool}

	// DMARC: 8 passing rows + 3 failing rows for acme.example.
	sum, err := s.IngestDMARC(ctx, []byte(dmarcXML))
	if err != nil {
		t.Fatalf("ingest dmarc: %v", err)
	}
	if sum.Domain != "acme.example" || sum.PassCount != 8 || sum.FailCount != 3 {
		t.Fatalf("dmarc summary = %+v, want domain=acme.example pass=8 fail=3", sum)
	}
	// Idempotent: re-ingesting the same report doesn't double-count.
	if _, err := s.IngestDMARC(ctx, []byte(dmarcXML)); err != nil {
		t.Fatal(err)
	}
	pass, fail, err := s.DMARCTotals(ctx, "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if pass != 8 || fail != 3 {
		t.Fatalf("DMARC totals = pass %d fail %d, want 8/3 (idempotency broken?)", pass, fail)
	}

	// TLS-RPT: 100 success + 5 failure sessions.
	ts, err := s.IngestTLSRPT(ctx, []byte(tlsrptJSON))
	if err != nil {
		t.Fatalf("ingest tlsrpt: %v", err)
	}
	if ts.Domain != "acme.example" || ts.SuccessCount != 100 || ts.FailureCount != 5 {
		t.Fatalf("tls summary = %+v, want domain=acme.example success=100 failure=5", ts)
	}
	success, failure, err := s.TLSTotals(ctx, "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if success != 100 || failure != 5 {
		t.Fatalf("TLS totals = %d/%d, want 100/5", success, failure)
	}

	t.Logf("OK: DMARC report parsed (pass=8 fail=3, idempotent) + TLS-RPT parsed (success=100 failure=5), per-domain totals queryable")
}
