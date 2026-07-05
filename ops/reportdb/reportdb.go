// Package reportdb ingests and stores aggregate deliverability reports on
// Postgres: DMARC aggregate (RUA) reports and SMTP TLS reporting (TLS-RPT).
// Reports arrive as email attachments at the domain's report addresses; this
// package parses them with the dmarcrpt/tlsrpt libraries (no reimplementation)
// and stores per-domain summaries the operator can query. This is the octo-mail
// equivalent of the dmarcdb/tlsrptdb, on the shared PG substrate.
package reportdb

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/tlsrpt"
)

// Store persists parsed reports.
type Store struct {
	Pool *pgxpool.Pool
}

// DMARCSummary is the stored per-report summary.
type DMARCSummary struct {
	Domain    string
	OrgName   string
	ReportID  string
	Begin     time.Time
	End       time.Time
	PassCount int64
	FailCount int64
}

// IngestDMARC parses a DMARC aggregate report (the XML body, possibly gzip/zip
// wrapped is handled by ParseMessageReport when given the full email) and stores
// a summary. Here we take the already-extracted XML report reader.
func (s *Store) IngestDMARC(ctx context.Context, xml []byte) (DMARCSummary, error) {
	fb, err := dmarcrpt.ParseReport(bytes.NewReader(xml))
	if err != nil {
		return DMARCSummary{}, err
	}
	var sum DMARCSummary
	sum.Domain = fb.PolicyPublished.Domain
	sum.OrgName = fb.ReportMetadata.OrgName
	sum.ReportID = fb.ReportMetadata.ReportID
	sum.Begin = time.Unix(fb.ReportMetadata.DateRange.Begin, 0).UTC()
	sum.End = time.Unix(fb.ReportMetadata.DateRange.End, 0).UTC()
	for _, rec := range fb.Records {
		n := int64(rec.Row.Count)
		// A row "passes" DMARC if the evaluated disposition is none AND at least
		// one of SPF/DKIM aligned-passed.
		if rec.Row.PolicyEvaluated.DKIM == dmarcrpt.DMARCPass || rec.Row.PolicyEvaluated.SPF == dmarcrpt.DMARCPass {
			sum.PassCount += n
		} else {
			sum.FailCount += n
		}
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO dmarc_reports (domain, org_name, report_id, date_begin, date_end, pass_count, fail_count)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (org_name, report_id) DO NOTHING`,
		sum.Domain, sum.OrgName, sum.ReportID, sum.Begin, sum.End, sum.PassCount, sum.FailCount)
	if err != nil {
		return DMARCSummary{}, err
	}
	return sum, nil
}

// TLSSummary is the stored per-report TLS-RPT summary.
type TLSSummary struct {
	Domain       string
	OrgName      string
	ReportID     string
	SuccessCount int64
	FailureCount int64
}

// IngestTLSRPT parses a TLS-RPT JSON report and stores a summary.
func (s *Store) IngestTLSRPT(ctx context.Context, jsonReport []byte) (TLSSummary, error) {
	rj, err := tlsrpt.Parse(bytes.NewReader(jsonReport))
	if err != nil {
		return TLSSummary{}, err
	}
	report := rj.Convert()
	var sum TLSSummary
	sum.OrgName = report.OrganizationName
	sum.ReportID = report.ReportID
	for _, p := range report.Policies {
		sum.SuccessCount += p.Summary.TotalSuccessfulSessionCount
		sum.FailureCount += p.Summary.TotalFailureSessionCount
		if sum.Domain == "" && p.Policy.Domain != "" {
			sum.Domain = p.Policy.Domain
		}
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO tlsrpt_reports (domain, org_name, report_id, success_count, failure_count)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (org_name, report_id) DO NOTHING`,
		sum.Domain, sum.OrgName, sum.ReportID, sum.SuccessCount, sum.FailureCount)
	if err != nil {
		return TLSSummary{}, err
	}
	return sum, nil
}

// DMARCTotals returns aggregate pass/fail counts for a domain across all stored
// reports — the operator's "are my legit senders passing DMARC?" view.
func (s *Store) DMARCTotals(ctx context.Context, domain string) (pass, fail int64, err error) {
	err = s.Pool.QueryRow(ctx,
		`SELECT COALESCE(sum(pass_count),0), COALESCE(sum(fail_count),0)
		 FROM dmarc_reports WHERE domain=$1`, domain).Scan(&pass, &fail)
	return
}

// TLSTotals returns aggregate success/failure session counts for a domain.
func (s *Store) TLSTotals(ctx context.Context, domain string) (success, failure int64, err error) {
	err = s.Pool.QueryRow(ctx,
		`SELECT COALESCE(sum(success_count),0), COALESCE(sum(failure_count),0)
		 FROM tlsrpt_reports WHERE domain=$1`, domain).Scan(&success, &failure)
	return
}
