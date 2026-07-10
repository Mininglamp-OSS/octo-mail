package reportdb

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
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

// querier is the subset of pgxpool.Pool / pgx.Tx that GenerateDMARCReport needs,
// so the report can be built either standalone (on the pool) or inside a fenced
// transaction (so its row set exactly matches the reported=true claim).
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// GenerateDMARCReport builds an RFC 7489 aggregate report (Feedback) for one
// from-domain from the unreported aggregate rows, marshaled to XML. Returns the
// XML, the rua address, and whether there was anything to report. orgDomain and
// orgEmail identify us (the reporting receiver). reportID must be stable/unique.
// The report's DateRange is derived from the actual days of the included rows, so
// it accurately states the window the data covers (RFC 7489 §7.2) rather than a
// fixed last-24h assumption. It reports the canonical (max) rua for the domain,
// scoping the report to rows carrying exactly that rua.
func (s *Store) GenerateDMARCReport(ctx context.Context, fromDomain, orgDomain, orgEmail, reportID string) ([]byte, string, bool, error) {
	var rua string
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(max(rua), '') FROM dmarc_agg WHERE from_domain=$1 AND NOT reported AND rua <> ''`,
		fromDomain).Scan(&rua); err != nil {
		return nil, "", false, err
	}
	if rua == "" {
		return nil, "", false, nil
	}
	body, _, ok, err := generateDMARCReport(ctx, s.Pool, fromDomain, rua, orgDomain, orgEmail, reportID)
	return body, rua, ok, err
}

// generateDMARCReport builds the report for exactly the rows carrying the given
// rua (so the report's contents match the address it will be sent to — the
// authorize-target and send-target are the same by construction). It also returns
// the actual [begin,end) window derived from the rows' day column.
func generateDMARCReport(ctx context.Context, q querier, fromDomain, rua, orgDomain, orgEmail, reportID string) (xmlOut []byte, window [2]time.Time, ok bool, err error) {
	rows, err := q.Query(ctx,
		`SELECT source_ip, spf_result, dkim_result, disposition, count, day
		 FROM dmarc_agg WHERE from_domain=$1 AND NOT reported AND rua=$2`, fromDomain, rua)
	if err != nil {
		return nil, window, false, err
	}
	var records []dmarcrpt.ReportRecord
	var minDay, maxDay time.Time
	for rows.Next() {
		var ip, spf, dkim, disp string
		var cnt int
		var day time.Time
		if err := rows.Scan(&ip, &spf, &dkim, &disp, &cnt, &day); err != nil {
			rows.Close()
			return nil, window, false, err
		}
		if minDay.IsZero() || day.Before(minDay) {
			minDay = day
		}
		if day.After(maxDay) {
			maxDay = day
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
		return nil, window, false, err
	}
	if len(records) == 0 {
		return nil, window, false, nil
	}
	// DateRange spans the included days: from the earliest day's 00:00 UTC to the
	// end of the latest day (exclusive), matching the rows actually aggregated.
	begin := minDay.UTC().Truncate(24 * time.Hour)
	end := maxDay.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	window = [2]time.Time{begin, end}

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
		return nil, window, false, err
	}
	out := append([]byte(xml.Header), body...)
	return out, window, true, nil
}

// FenceFunc runs fn inside a leadership-fenced transaction, committing only if
// the caller still holds leadership at its epoch (else returns ha.ErrFenced
// without running fn). It is exactly ha.Leader.FenceExec; taking it as a param
// keeps reportdb decoupled from ops/ha. The transaction runs at REPEATABLE READ,
// so a read-then-write over the same rows sees one snapshot.
type FenceFunc func(ctx context.Context, fn func(pgx.Tx) error) error

// RUAResult is the outcome of authorizing an aggregate report's rua address.
type RUAResult int

const (
	// RUAAuthorized: the rua domain is permitted to receive our reports for the
	// reported domain (same-domain, or a valid RFC 7489 §7.1 opt-in). Send.
	RUAAuthorized RUAResult = iota
	// RUADenied: the rua is a third party with NO opt-in — a permanent condition.
	// Do not send; claim the rows so we don't retry a forever-unauthorized rua.
	RUADenied
	// RUATransient: the authorization lookup failed transiently (e.g. DNS
	// temperror). Neither send nor claim — leave the rows so the next tick retries,
	// rather than permanently dropping a window for a legitimate rua.
	RUATransient
)

// RUAAuthorizer classifies whether the rua address may receive DMARC aggregate
// reports for reportedDomain, per RFC 7489 §7.1 (the
// "<reported>._report._dmarc.<rua-domain>" opt-in TXT record). It MUST NOT return
// RUAAuthorized for an unverified third-party rua, or octo-mail becomes an
// attacker-steerable mail reflector (a sender publishes rua=mailto:victim@x). A
// same-domain rua is authorized without a lookup. It distinguishes a permanent
// denial from a transient lookup failure so a temporary DNS error doesn't
// permanently drop a legitimate window. Injected to keep reportdb decoupled from
// dns/mox.
type RUAAuthorizer func(ctx context.Context, reportedDomain, ruaAddr string) RUAResult

// SendDMARCReportFenced is the leader-gated, promotion-safe DMARC aggregate
// sender (H18): the first NON-idempotent leader job, so it must not double-send
// across a PostgreSQL failover where two nodes briefly believe they lead.
//
// Order of operations:
//  1. Peek (unfenced) at the pending rua for this domain; if none, nothing to do.
//  2. Authorize the rua (RFC 7489 §7.1). A TRANSIENT failure returns without
//     claiming, so the next tick retries; a permanent DENY still claims the rows
//     (below) so we don't loop on a forever-unauthorized rua, but sends nothing.
//  3. In ONE fenced REPEATABLE READ transaction, generate the report AND claim its
//     rows (UPDATE ... reported=true). One snapshot ⇒ the report's rows exactly
//     match the claimed rows: no row inserted/incremented concurrently is marked
//     reported without appearing in the report. A fenced old leader's tx rolls
//     back (ha.ErrFenced) and never claims; only the node whose claim commits
//     proceeds.
//  4. Only if authorized, enqueue the report AFTER the fenced commit (Sender.Submit
//     opens its own queue tx and can't enroll in the fence's tx). At-most-once
//     marking with an at-least-once send attempt: a crash/Submit error between
//     commit and enqueue drops a single window, acceptable for aggregate reports
//     and strictly safer than a double-send.
//
// Returns whether a report was enqueued.
func (s *Store) SendDMARCReportFenced(ctx context.Context, fence FenceFunc, authorized RUAAuthorizer, sender Sender, tenantID, accountID int64, fromDomain, orgDomain, orgEmail string) (bool, error) {
	reportID := orgDomain + "-" + fromDomain + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)

	// Pick ONE canonical rua for this domain (the lexical max of pending rows) and
	// use it for authorization, report generation, AND the claim — so the address
	// we authorize is exactly the address we send to. `rua` is not in dmarc_agg's
	// unique key, so one from_domain can hold rows with different rua values (a
	// sender can rotate its published rua= mid-window); authorizing max(rua) but
	// sending to some other row's rua would let an unauthorized third-party rua
	// receive the report. Rows carrying a DIFFERENT rua are left unreported and get
	// authorized against their own value on a later tick.
	var rua string
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(max(rua), '') FROM dmarc_agg WHERE from_domain=$1 AND NOT reported AND rua <> ''`,
		fromDomain).Scan(&rua); err != nil {
		return false, err
	}
	if rua == "" {
		return false, nil // nothing pending, or no published rua
	}
	// Classify authorization of the canonical rua. Transient → do not claim, retry.
	auth := RUAAuthorized
	if authorized != nil {
		auth = authorized(ctx, fromDomain, rua)
	}
	if auth == RUATransient {
		return false, nil // leave rows unreported; next tick retries
	}

	// Generate + claim atomically in the fenced (RepeatableRead) transaction,
	// scoped to exactly the canonical rua's rows.
	var xmlBody []byte
	var claimed bool
	if err := fence(ctx, func(tx pgx.Tx) error {
		body, _, ok, e := generateDMARCReport(ctx, tx, fromDomain, rua, orgDomain, orgEmail, reportID)
		if e != nil || !ok {
			return e // nothing to report for this rua → claimed stays false
		}
		ct, e := tx.Exec(ctx, `UPDATE dmarc_agg SET reported=true WHERE from_domain=$1 AND NOT reported AND rua=$2`, fromDomain, rua)
		if e != nil {
			return e
		}
		xmlBody, claimed = body, ct.RowsAffected() > 0
		return nil
	}); err != nil {
		return false, err
	}
	if !claimed {
		return false, nil // nothing to report or already claimed
	}
	// A permanent denial claimed this rua's rows (so we don't loop) but sends nothing.
	if auth == RUADenied {
		return false, nil
	}
	// Enqueue exactly once — to the SAME rua we authorized and generated for.
	msg := buildReportMessage(orgEmail, rua, "Report Domain: "+fromDomain+" Submitter: "+orgDomain,
		"application/xml", "dmarc-report.xml", xmlBody)
	if _, err := sender.Submit(ctx, tenantID, accountID, orgEmail, []string{rua}, msg); err != nil {
		return false, err
	}
	return true, nil
}

// UnreportedDMARCDomains returns the from-domains that have unreported aggregate
// rows with a non-empty reporting address — the work list for the report
// scheduler. A domain with rows but no published rua is skipped (nothing to send).
func (s *Store) UnreportedDMARCDomains(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT DISTINCT from_domain FROM dmarc_agg WHERE NOT reported AND rua <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
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
