package reportdb_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/ops/reportdb"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dmarcrpt"
)

// stubSender captures the enqueued report message.
type stubSender struct {
	got [][]byte
	to  []string
}

func (s *stubSender) Submit(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error) {
	s.got = append(s.got, raw)
	s.to = append(s.to, rcptTo...)
	return []int64{1}, nil
}

// TestReportGeneration proves P0-3: DMARC aggregate rows accumulate, a valid
// RFC 7489 XML report is generated (round-trips through the parser), it is
// enqueued to the rua address, source rows are marked reported; and a TLS-RPT
// JSON report generates + round-trips through the parser.
func TestReportGeneration(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS dmarc_agg (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, from_domain text NOT NULL, rua text NOT NULL DEFAULT '', source_ip text NOT NULL, spf_result text NOT NULL, dkim_result text NOT NULL, disposition text NOT NULL, count bigint NOT NULL DEFAULT 0, day date NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'), reported boolean NOT NULL DEFAULT false, UNIQUE (from_domain, source_ip, spf_result, dkim_result, disposition, day))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	pool.Exec(ctx, `TRUNCATE dmarc_agg RESTART IDENTITY`)
	s := &reportdb.Store{Pool: pool}

	// Accumulate received-mail evaluations for sender.example.
	for i := 0; i < 5; i++ {
		if err := s.RecordDMARCAgg(ctx, "sender.example", "rua@sender.example", "203.0.113.5", "pass", "pass", "none"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := s.RecordDMARCAgg(ctx, "sender.example", "rua@sender.example", "198.51.100.9", "fail", "fail", "reject"); err != nil {
			t.Fatal(err)
		}
	}

	// Generate the XML report and prove it parses back (valid RFC 7489).
	xmlBody, rua, ok, err := s.GenerateDMARCReport(ctx, "sender.example", "mx.example.com", "postmaster@example.com",
		"rid-1", time.Now().Add(-24*time.Hour), time.Now())
	if err != nil || !ok {
		t.Fatalf("generate dmarc: ok=%v err=%v", ok, err)
	}
	if rua != "rua@sender.example" {
		t.Fatalf("rua = %q, want rua@sender.example", rua)
	}
	fb, err := dmarcrpt.ParseReport(bytes.NewReader(xmlBody))
	if err != nil {
		t.Fatalf("generated DMARC XML does not parse: %v", err)
	}
	if fb.PolicyPublished.Domain != "sender.example" {
		t.Fatalf("parsed report domain = %q", fb.PolicyPublished.Domain)
	}
	var total int
	for _, r := range fb.Records {
		total += r.Row.Count
	}
	if total != 7 {
		t.Fatalf("report total count = %d, want 7 (5 pass + 2 fail)", total)
	}

	// Send via stub, assert enqueued to rua + rows marked reported.
	sender := &stubSender{}
	sent, err := s.SendDMARCReport(ctx, sender, 1, 1, "sender.example", "mx.example.com", "postmaster@example.com")
	if err != nil || !sent {
		t.Fatalf("send dmarc: sent=%v err=%v", sent, err)
	}
	if len(sender.got) != 1 || len(sender.to) != 1 || sender.to[0] != "rua@sender.example" {
		t.Fatalf("report not enqueued to rua: to=%v", sender.to)
	}
	var unreported int
	pool.QueryRow(ctx, `SELECT count(*) FROM dmarc_agg WHERE from_domain='sender.example' AND NOT reported`).Scan(&unreported)
	if unreported != 0 {
		t.Fatalf("%d rows still unreported after send", unreported)
	}

	// TLS-RPT report generation round-trips through the parser.
	tlsBody, err := reportdb.GenerateTLSReport("mx.example.com", "tls-1", "sender.example",
		time.Now().Add(-24*time.Hour), time.Now(), 100, 3)
	if err != nil {
		t.Fatalf("generate tls: %v", err)
	}
	sum, err := s.IngestTLSRPT(ctx, tlsBody)
	if err != nil {
		t.Fatalf("generated TLS-RPT JSON does not parse/ingest: %v", err)
	}
	if sum.SuccessCount != 100 || sum.FailureCount != 3 {
		t.Fatalf("TLS report round-trip = %d/%d, want 100/3", sum.SuccessCount, sum.FailureCount)
	}

	t.Logf("OK: DMARC agg → valid XML (parses, 7 records) → enqueued to rua → marked reported; TLS-RPT JSON generated + round-trips")
}
