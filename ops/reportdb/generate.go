package reportdb

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/tlsrpt"
)

// Sender enqueues a generated report for outbound delivery to the reporting
// address. Wired to the submit.Submitter in production; a stub in tests.
type Sender interface {
	Submit(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error)
}

// RecordDMARCAgg accumulates one received message's DMARC evaluation into the
// aggregate source (upsert by the natural key + day). rua is the sending
// domain's aggregate reporting address (from its DMARC record).
func (s *Store) RecordDMARCAgg(ctx context.Context, fromDomain, rua, sourceIP, spf, dkim, disposition string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO dmarc_agg (from_domain, rua, source_ip, spf_result, dkim_result, disposition, count)
		 VALUES ($1,$2,$3,$4,$5,$6,1)
		 ON CONFLICT (from_domain, source_ip, spf_result, dkim_result, disposition, day)
		 DO UPDATE SET count = dmarc_agg.count + 1, rua = EXCLUDED.rua`,
		fromDomain, rua, sourceIP, spf, dkim, disposition)
	return err
}

// GenerateDMARCReport builds an RFC 7489 aggregate report (Feedback) for one
// from-domain from the unreported aggregate rows, marshaled to XML. Returns the
// XML, the rua address, and whether there was anything to report. orgDomain and
// orgEmail identify us (the reporting receiver). reportID must be stable/unique.
func (s *Store) GenerateDMARCReport(ctx context.Context, fromDomain, orgDomain, orgEmail, reportID string, begin, end time.Time) ([]byte, string, bool, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT rua, source_ip, spf_result, dkim_result, disposition, count
		 FROM dmarc_agg WHERE from_domain=$1 AND NOT reported`, fromDomain)
	if err != nil {
		return nil, "", false, err
	}
	var rua string
	var records []dmarcrpt.ReportRecord
	for rows.Next() {
		var r, ip, spf, dkim, disp string
		var cnt int
		if err := rows.Scan(&r, &ip, &spf, &dkim, &disp, &cnt); err != nil {
			rows.Close()
			return nil, "", false, err
		}
		if r != "" {
			rua = r
		}
		records = append(records, dmarcrpt.ReportRecord{
			Row: dmarcrpt.Row{
				SourceIP: ip,
				Count:    cnt,
				PolicyEvaluated: dmarcrpt.PolicyEvaluated{
					Disposition: dmarcrpt.Disposition(disp),
					DKIM:        dmarcrpt.DMARCResult(dkim),
					SPF:         dmarcrpt.DMARCResult(spf),
				},
			},
			Identifiers: dmarcrpt.Identifiers{HeaderFrom: fromDomain},
			AuthResults: dmarcrpt.AuthResults{
				SPF: []dmarcrpt.SPFAuthResult{{Domain: fromDomain, Result: dmarcrpt.SPFResult(spf)}},
			},
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", false, err
	}
	if len(records) == 0 {
		return nil, "", false, nil
	}

	fb := dmarcrpt.Feedback{
		Version: "1.0",
		ReportMetadata: dmarcrpt.ReportMetadata{
			OrgName:   orgDomain,
			Email:     orgEmail,
			ReportID:  reportID,
			DateRange: dmarcrpt.DateRange{Begin: begin.Unix(), End: end.Unix()},
		},
		PolicyPublished: dmarcrpt.PolicyPublished{Domain: fromDomain, Policy: "none", Percentage: 100},
		Records:         records,
	}
	body, err := xml.MarshalIndent(fb, "", "  ")
	if err != nil {
		return nil, "", false, err
	}
	out := append([]byte(xml.Header), body...)
	return out, rua, true, nil
}

// SendDMARCReport generates and enqueues the aggregate report for a from-domain,
// then marks its source rows reported. Returns whether a report was sent. The
// report is wrapped in a minimal RFC822 message to the rua address.
func (s *Store) SendDMARCReport(ctx context.Context, sender Sender, tenantID, accountID int64, fromDomain, orgDomain, orgEmail string) (bool, error) {
	end := time.Now().UTC()
	begin := end.Add(-24 * time.Hour)
	reportID := orgDomain + "-" + fromDomain + "-" + strconv.FormatInt(end.Unix(), 10)
	xmlBody, rua, ok, err := s.GenerateDMARCReport(ctx, fromDomain, orgDomain, orgEmail, reportID, begin, end)
	if err != nil || !ok {
		return false, err
	}
	if rua == "" {
		return false, nil // no reporting address published
	}
	msg := buildReportMessage(orgEmail, rua, "Report Domain: "+fromDomain+" Submitter: "+orgDomain,
		"application/xml", "dmarc-report.xml", xmlBody)
	if _, err := sender.Submit(ctx, tenantID, accountID, orgEmail, []string{rua}, msg); err != nil {
		return false, err
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE dmarc_agg SET reported=true WHERE from_domain=$1 AND NOT reported`, fromDomain); err != nil {
		return true, err
	}
	return true, nil
}

// GenerateTLSReport builds a TLS-RPT JSON report for a domain from its stored
// success/failure counters (here summarized from tlsrpt_reports we track for our
// own sending, or a supplied summary). This produces a valid RFC 8460 report.
func GenerateTLSReport(orgName, reportID, domain string, begin, end time.Time, success, failure int64) ([]byte, error) {
	rj := tlsrpt.ReportJSON{
		OrganizationName: orgName,
		DateRange:        tlsrpt.TLSRPTDateRangeJSON{Start: begin, End: end},
		ContactInfo:      "postmaster@" + orgName,
		ReportID:         reportID,
		Policies: []tlsrpt.ResultJSON{{
			Policy:  tlsrpt.ResultPolicyJSON{Type: "sts", Domain: domain},
			Summary: tlsrpt.SummaryJSON{TotalSuccessfulSessionCount: success, TotalFailureSessionCount: failure},
		}},
	}
	return jsonMarshal(rj)
}

// buildReportMessage wraps a report body in a minimal MIME message.
func buildReportMessage(from, to, subject, contentType, filename string, body []byte) []byte {
	return []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: %s\r\nContent-Disposition: attachment; filename=\"%s\"\r\n\r\n%s\r\n",
		from, to, subject, contentType, filename, body))
}

func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
