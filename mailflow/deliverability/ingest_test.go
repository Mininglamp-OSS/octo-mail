package deliverability_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIngestReport proves the H9 inbound loop: mail delivered to the VERP bounce
// domain is attributed to the sending tenant and recorded as a reputation event —
// both for an ARF complaint (via the embedded original's VERP) and a DSN bounce
// (via the VERP recipient localpart the DSN was addressed to).
func TestIngestReport(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS reputation_events (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, account_id bigint, kind smallint NOT NULL, remote_domain text NOT NULL, ip_id bigint, at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	// The canonical reputation_events has an FK to tenants; ensure our tenant id
	// exists. Create tenants if isolated, then insert a row at the fixed id.
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE reputation_events RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	// Insert tenants up to id 7 so the FK is satisfiable at the fixed test id.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (name) SELECT 'tt'||g FROM generate_series(1,7) g`); err != nil {
		t.Fatal(err)
	}

	const tenantID, msgID = int64(7), int64(42)
	key := []byte("verp-signing-key")
	svc := &deliverability.Service{Pool: pool}
	verp := deliverability.SignedVERPToken(tenantID, msgID, key)

	countKind := func(kind int) int {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM reputation_events WHERE tenant_id=$1 AND kind=$2`, tenantID, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// --- DSN bounce path: a plain (non-ARF) message addressed to the VERP
	// recipient. Attribution comes from the recipient localpart alone. ---
	dsn := []byte("From: mailer-daemon@remote.example\r\nTo: " + verp + "@bounces.example\r\n" +
		"Subject: Delivery Status Notification (Failure)\r\n\r\n550 user unknown\r\n")
	c, ok, err := svc.IngestReport(ctx, verp, key, dsn)
	if err != nil {
		t.Fatalf("IngestReport(dsn): %v", err)
	}
	if !ok || c.TenantID != tenantID || c.MsgID != msgID || c.Kind != deliverability.KindBounce {
		t.Fatalf("DSN attribution wrong: ok=%v c=%+v", ok, c)
	}
	if countKind(deliverability.KindBounce) != 1 {
		t.Fatalf("expected 1 bounce event, got %d", countKind(deliverability.KindBounce))
	}

	// --- ARF complaint path: a multipart/report ARF carrying the original's VERP
	// return-path. Attribution + complained domain come from the report. ---
	arf := []byte("From: fbl@provider.example\r\nTo: " + verp + "@bounces.example\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: message/feedback-report\r\n\r\n" +
		"Original-Rcpt-To: <victim@complainer.example>\r\n\r\n" +
		"--b1\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Return-Path: <" + verp + "@bounces.example>\r\nSubject: our mail\r\n\r\nbody\r\n" +
		"--b1--\r\n")
	c2, ok2, err := svc.IngestReport(ctx, verp, key, arf)
	if err != nil {
		t.Fatalf("IngestReport(arf): %v", err)
	}
	if !ok2 || c2.TenantID != tenantID || c2.Kind != deliverability.KindComplaint {
		t.Fatalf("ARF attribution wrong: ok=%v c=%+v", ok2, c2)
	}
	if countKind(deliverability.KindComplaint) != 1 {
		t.Fatalf("expected 1 complaint event, got %d", countKind(deliverability.KindComplaint))
	}

	// --- Unattributable: a message with no VERP anywhere → ok=false, no event. ---
	_, ok3, err := svc.IngestReport(ctx, "postmaster", key, []byte("Subject: hi\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatalf("IngestReport(unattributable): %v", err)
	}
	if ok3 {
		t.Fatal("unattributable message was attributed")
	}

	// --- Forged token: an attacker addresses bounces+<victim>.<n> with NO valid
	// MAC. It must not authenticate, so no reputation event is attributed to the
	// victim tenant (closes the cross-tenant DoS). ---
	forged := "bounces+7.999.aaaaaaaaaaaaaaaa"
	beforeB, beforeC := countKind(deliverability.KindBounce), countKind(deliverability.KindComplaint)
	_, okF, err := svc.IngestReport(ctx, forged, key, []byte("Subject: failure\r\n\r\n550 nope\r\n"))
	if err != nil {
		t.Fatalf("IngestReport(forged): %v", err)
	}
	if okF {
		t.Fatal("forged VERP token was accepted — cross-tenant attribution DoS open")
	}
	if countKind(deliverability.KindBounce) != beforeB || countKind(deliverability.KindComplaint) != beforeC {
		t.Fatal("forged token recorded a reputation event")
	}

	t.Logf("OK: signed DSN bounce + ARF complaint attributed; unattributable ignored; forged token rejected (no event)")
}
