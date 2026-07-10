package reportdb_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/ops/reportdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// errFenced stands in for ha.ErrFenced (reportdb must not import ops/ha).
var errFenced = errors.New("fenced")

// realFence runs fn in a real transaction on the pool — the not-fenced case.
func realFence(pool *pgxpool.Pool) reportdb.FenceFunc {
	return func(ctx context.Context, fn func(pgx.Tx) error) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
}

// fencedFence simulates a node that has been fenced: it never runs fn and returns
// errFenced (as ha.Leader.FenceExec does when the lease is superseded).
func fencedFence(ctx context.Context, fn func(pgx.Tx) error) error { return errFenced }

func openAggPool(t *testing.T) *pgxpool.Pool {
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
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS dmarc_agg (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, from_domain text NOT NULL, rua text NOT NULL DEFAULT '', source_ip text NOT NULL, spf_result text NOT NULL, dkim_result text NOT NULL, disposition text NOT NULL, count bigint NOT NULL DEFAULT 0, day date NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'), reported boolean NOT NULL DEFAULT false, UNIQUE (from_domain, source_ip, spf_result, dkim_result, disposition, day))`); err != nil {
		t.Fatal(err)
	}
	pool.Exec(ctx, `TRUNCATE dmarc_agg RESTART IDENTITY`)
	t.Cleanup(pool.Close)
	return pool
}

// allowAllRUA authorizes every rua (the not-a-reflector-target case).
func allowAllRUA(ctx context.Context, reportedDomain, ruaAddr string) reportdb.RUAResult {
	return reportdb.RUAAuthorized
}

// denyAllRUA rejects every rua (simulates an unauthorized third-party rua).
func denyAllRUA(ctx context.Context, reportedDomain, ruaAddr string) reportdb.RUAResult {
	return reportdb.RUADenied
}

// TestSendDMARCReportFenced proves the H18 promotion-safe send: while leader
// (real fence) it enqueues once and marks rows reported; once fenced it neither
// enqueues nor marks reported; and a second leader racing the same domain (after
// the first already claimed it) enqueues nothing (0 rows to claim).
func TestSendDMARCReportFenced(t *testing.T) {
	ctx := context.Background()
	pool := openAggPool(t)
	s := &reportdb.Store{Pool: pool}
	for i := 0; i < 3; i++ {
		if err := s.RecordDMARCAgg(ctx, "sender.example", "rua@sender.example", "203.0.113.5", "pass", "pass", "none"); err != nil {
			t.Fatal(err)
		}
	}

	// Fenced node: must NOT send and must NOT mark reported.
	sender := &stubSender{}
	sent, err := s.SendDMARCReportFenced(ctx, fencedFence, allowAllRUA, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err == nil || !errors.Is(err, errFenced) {
		t.Fatalf("fenced send err = %v, want errFenced", err)
	}
	if sent || len(sender.got) != 0 {
		t.Fatalf("fenced node sent a report (sent=%v msgs=%d) — fence did not prevent the side effect", sent, len(sender.got))
	}
	var unreported int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_agg WHERE from_domain='sender.example' AND NOT reported`).Scan(&unreported)
	if unreported == 0 {
		t.Fatalf("fenced node marked rows reported — claim was not rolled back")
	}

	// Leader: sends once, marks reported.
	sent, err = s.SendDMARCReportFenced(ctx, realFence(pool), allowAllRUA, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err != nil || !sent {
		t.Fatalf("leader send: sent=%v err=%v", sent, err)
	}
	if len(sender.got) != 1 || len(sender.to) != 1 || sender.to[0] != "rua@sender.example" {
		t.Fatalf("leader did not enqueue exactly one report to rua: to=%v", sender.to)
	}

	// Re-run over an already-claimed domain: nothing left to claim, nothing sent.
	// (This proves row-claim idempotency on re-run; the concurrent-fencing guarantee
	// itself is covered by ops/ha's own tests, not this sequential realFence stub.)
	sent, err = s.SendDMARCReportFenced(ctx, realFence(pool), allowAllRUA, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err != nil {
		t.Fatalf("second send err: %v", err)
	}
	if sent || len(sender.got) != 1 {
		t.Fatalf("second leader re-sent an already-reported domain (sent=%v total msgs=%d) — double send", sent, len(sender.got))
	}
	t.Logf("OK: fenced node sends nothing and rolls back its claim; leader sends once; a re-run finds nothing to claim (no double send)")
}

// TestSendDMARCReportRUAReflectionBlocked proves the RFC 7489 §7.1 anti-reflection
// control: when the rua's domain is NOT authorized to receive reports for the
// reported domain (denyAllRUA simulates a third-party rua with no opt-in record),
// no report is enqueued — so a sender publishing rua=mailto:victim@x cannot steer
// octo-mail into mailing a report to an arbitrary address. The rows are still
// claimed (marked reported) so the unsendable window doesn't loop forever.
func TestSendDMARCReportRUAReflectionBlocked(t *testing.T) {
	ctx := context.Background()
	pool := openAggPool(t)
	s := &reportdb.Store{Pool: pool}
	if err := s.RecordDMARCAgg(ctx, "evil.example", "victim@target.example", "203.0.113.9", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{}
	sent, err := s.SendDMARCReportFenced(ctx, realFence(pool), denyAllRUA, sender, 1, 1, "evil.example", "mx.example.com", "postmaster@example.com")
	if err != nil {
		t.Fatalf("send err: %v", err)
	}
	if sent || len(sender.got) != 0 {
		t.Fatalf("report sent to unauthorized third-party rua (sent=%v msgs=%d) — reflection not blocked", sent, len(sender.got))
	}
	var unreported int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_agg WHERE from_domain='evil.example' AND NOT reported`).Scan(&unreported)
	if unreported != 0 {
		t.Fatalf("unauthorized-rua rows left unreported (%d) — would loop forever", unreported)
	}
	t.Logf("OK: report to an unauthorized third-party rua is blocked (no send), rows still claimed")
}

// TestSendDMARCReportRUAConsistentTarget proves the authorize-target and
// send-target are the same rua even when one from_domain has rows carrying
// DIFFERENT rua values (a sender rotating its published rua= mid-window). The
// authorizer only permits a specific address; the report must be generated for
// and sent to exactly that authorized rua — never a co-pending unauthorized one.
func TestSendDMARCReportRUAConsistentTarget(t *testing.T) {
	ctx := context.Background()
	pool := openAggPool(t)
	s := &reportdb.Store{Pool: pool}
	// Two unreported rows for one from_domain with different rua values. The
	// canonical (max) rua is the one lexically greater; make that the ONLY one the
	// authorizer permits, and an attacker-controlled address the other.
	const authorizedRUA = "zzz-authorized@self.example" // lexical max
	const evilRUA = "aaa-victim@target.example"
	if err := s.RecordDMARCAgg(ctx, "sender.example", authorizedRUA, "203.0.113.1", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDMARCAgg(ctx, "sender.example", evilRUA, "203.0.113.2", "fail", "fail", "reject"); err != nil {
		t.Fatal(err)
	}
	// Authorize ONLY the canonical rua; deny anything else.
	onlyAuthorized := func(ctx context.Context, reportedDomain, ruaAddr string) reportdb.RUAResult {
		if ruaAddr == authorizedRUA {
			return reportdb.RUAAuthorized
		}
		return reportdb.RUADenied
	}
	sender := &stubSender{}
	sent, err := s.SendDMARCReportFenced(ctx, realFence(pool), onlyAuthorized, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err != nil {
		t.Fatalf("send err: %v", err)
	}
	// A report is sent, and ONLY to the authorized rua — never the evil one.
	if !sent || len(sender.to) != 1 {
		t.Fatalf("want exactly one send, got sent=%v to=%v", sent, sender.to)
	}
	if sender.to[0] != authorizedRUA {
		t.Fatalf("report sent to %q, want the authorized rua %q (authorize/send divergence)", sender.to[0], authorizedRUA)
	}
	// The evil rua's row must remain unreported (it was never authorized), so it is
	// re-evaluated on a later tick against its OWN address, not smuggled into this
	// report.
	var evilUnreported int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_agg WHERE from_domain='sender.example' AND rua=$1 AND NOT reported`, evilRUA).Scan(&evilUnreported)
	if evilUnreported != 1 {
		t.Fatalf("evil-rua row unreported=%d, want 1 (must not be claimed under the authorized rua's report)", evilUnreported)
	}
	t.Logf("OK: report authorized for and sent to the same rua; a co-pending unauthorized rua is neither sent to nor claimed")
}

// TestSendDMARCReportRUATransient proves a TRANSIENT authorization failure (e.g. a
// DNS temperror) neither sends nor claims — the rows stay unreported so the next
// tick retries, rather than permanently dropping a legitimate window (P1-d).
func TestSendDMARCReportRUATransient(t *testing.T) {
	ctx := context.Background()
	pool := openAggPool(t)
	s := &reportdb.Store{Pool: pool}
	if err := s.RecordDMARCAgg(ctx, "sender.example", "rua@third-party.example", "203.0.113.5", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	transient := func(ctx context.Context, reportedDomain, ruaAddr string) reportdb.RUAResult {
		return reportdb.RUATransient
	}
	sender := &stubSender{}
	sent, err := s.SendDMARCReportFenced(ctx, realFence(pool), transient, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err != nil {
		t.Fatalf("send err: %v", err)
	}
	if sent || len(sender.got) != 0 {
		t.Fatalf("transient auth failure still sent (sent=%v msgs=%d)", sent, len(sender.got))
	}
	var unreported int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_agg WHERE from_domain='sender.example' AND NOT reported`).Scan(&unreported)
	if unreported == 0 {
		t.Fatalf("transient auth failure marked rows reported — window permanently dropped instead of retried")
	}
	t.Logf("OK: a transient rua-authorization failure leaves rows unreported for the next tick (no permanent drop)")
}

// TestIngestMessageBomb proves the decompression budget: a small gzip that expands
// past the single-stream cap is rejected (not silently truncated and mis-parsed).
func TestIngestMessageBomb(t *testing.T) {
	ctx := context.Background()
	pool := openReportsPool(t)
	s := &reportdb.Store{Pool: pool}

	// A gzip of ~60 MiB of zeros: well past the 50 MiB single-stream cap, but the
	// compressed attachment is tiny (high ratio) — the decompression-bomb shape.
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := io.Copy(w, io.LimitReader(zeroReader{}, 60<<20)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	var b bytes.Buffer
	b.WriteString("From: r@acme.example\r\nTo: reports@mx.example.com\r\nSubject: Report\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: application/gzip\r\nContent-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-Disposition: attachment; filename=\"bomb.gz\"\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString(buf.Bytes()))
	b.WriteString("\r\n")

	_, err := s.IngestMessage(ctx, b.Bytes(), nil)
	if err == nil {
		t.Fatalf("oversized decompressed payload was not rejected (no error)")
	}
	t.Logf("OK: an over-cap decompressed attachment is rejected (%v), not silently truncated", err)
}

// zeroReader yields an endless stream of zero bytes (compresses to ~nothing).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestUnreportedDMARCDomains proves the scheduler work-list: only domains with
// unreported rows AND a non-empty rua are returned.
func TestUnreportedDMARCDomains(t *testing.T) {
	ctx := context.Background()
	pool := openAggPool(t)
	s := &reportdb.Store{Pool: pool}
	if err := s.RecordDMARCAgg(ctx, "with-rua.example", "rua@x.example", "203.0.113.1", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDMARCAgg(ctx, "no-rua.example", "", "203.0.113.2", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	domains, err := s.UnreportedDMARCDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0] != "with-rua.example" {
		t.Fatalf("work list = %v, want [with-rua.example] (no-rua domain must be skipped)", domains)
	}
	t.Logf("OK: scheduler work-list includes only unreported domains with a published rua")
}

// TestIngestMessageExtraction proves the inbound extraction path: a gzipped DMARC
// XML attachment and a gzipped TLS-RPT JSON attachment in RFC822 messages are
// each extracted, sniffed, and ingested.
func TestIngestMessageExtraction(t *testing.T) {
	ctx := context.Background()
	pool := openReportsPool(t)
	s := &reportdb.Store{Pool: pool}

	gz := func(b []byte) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}
	// A minimal valid DMARC aggregate report and TLS-RPT report.
	dmarcXML := []byte(`<?xml version="1.0"?><feedback><report_metadata><org_name>acme</org_name><email>dmarc@acme.example</email><report_id>rid-extract-1</report_id><date_range><begin>1000</begin><end>2000</end></date_range></report_metadata><policy_published><domain>sender.example</domain><p>none</p></policy_published><record><row><source_ip>203.0.113.5</source_ip><count>4</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>sender.example</header_from></identifiers><auth_results></auth_results></record></feedback>`)
	tlsJSON := []byte(`{"organization-name":"acme","date-range":{"start-datetime":"2026-01-01T00:00:00Z","end-datetime":"2026-01-02T00:00:00Z"},"report-id":"rid-extract-tls-1","policies":[{"policy":{"policy-type":"sts","policy-domain":"sender.example"},"summary":{"total-successful-session-count":42,"total-failure-session-count":1}}]}`)

	mkMsg := func(ctype, filename string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("From: reporter@acme.example\r\nTo: reports@mx.example.com\r\nSubject: Report\r\nMIME-Version: 1.0\r\n")
		b.WriteString("Content-Type: " + ctype + "\r\nContent-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" + filename + "\"\r\n\r\n")
		// base64 with CRLF line wrapping at 76 cols (MIME).
		enc := base64.StdEncoding.EncodeToString(body)
		for len(enc) > 76 {
			b.WriteString(enc[:76])
			b.WriteString("\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc)
		b.WriteString("\r\n")
		return b.Bytes()
	}

	// owned allows the report domains used in the fixtures (nil would also work;
	// this exercises the gate on the accept path).
	owned := func(ctx context.Context, domain string) bool { return domain == "sender.example" }

	kind, err := s.IngestMessage(ctx, mkMsg("application/gzip", "report.xml.gz", gz(dmarcXML)), owned)
	if err != nil || kind != "dmarc" {
		t.Fatalf("dmarc gzip ingest: kind=%q err=%v", kind, err)
	}
	kind, err = s.IngestMessage(ctx, mkMsg("application/tlsrpt+gzip", "report.json.gz", gz(tlsJSON)), owned)
	if err != nil || kind != "tlsrpt" {
		t.Fatalf("tlsrpt gzip ingest: kind=%q err=%v", kind, err)
	}
	// A malformed/empty attachment must error, not panic or wedge.
	if _, err := s.IngestMessage(ctx, mkMsg("application/gzip", "junk.gz", gz([]byte("not a report"))), owned); err == nil {
		t.Fatalf("expected error for non-report payload")
	}
	// A report for an UNOWNED domain must be rejected and stored nothing.
	unownedXML := []byte(`<?xml version="1.0"?><feedback><report_metadata><org_name>evil</org_name><email>e@evil.example</email><report_id>rid-unowned</report_id><date_range><begin>1000</begin><end>2000</end></date_range></report_metadata><policy_published><domain>victim.example</domain><p>none</p></policy_published><record><row><source_ip>203.0.113.9</source_ip><count>9</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>victim.example</header_from></identifiers><auth_results></auth_results></record></feedback>`)
	if _, err := s.IngestMessage(ctx, mkMsg("application/gzip", "unowned.xml.gz", gz(unownedXML)), owned); err == nil {
		t.Fatalf("expected rejection for a report about an unowned domain")
	}
	var nUnowned int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_reports WHERE report_id='rid-unowned'`).Scan(&nUnowned)
	if nUnowned != 0 {
		t.Fatalf("unowned-domain report was stored (%d rows) — ingest ownership gate bypassed", nUnowned)
	}

	var nd, nt int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_reports WHERE report_id='rid-extract-1'`).Scan(&nd)
	pool.QueryRow(ctx, `SELECT count(*) FROM tlsrpt_reports WHERE report_id='rid-extract-tls-1'`).Scan(&nt)
	if nd != 1 || nt != 1 {
		t.Fatalf("stored dmarc=%d tlsrpt=%d, want 1/1", nd, nt)
	}
	t.Logf("OK: gzipped DMARC-XML and TLS-RPT-JSON attachments extracted, sniffed, and ingested; junk + unowned-domain rejected")
}

func openReportsPool(t *testing.T) *pgxpool.Pool {
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
	t.Cleanup(pool.Close)
	return pool
}
