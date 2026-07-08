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
	// The affected domain is now taken from the authenticated outbound send record
	// (queue_log.rcpt_to keyed by the signed msgID), NOT the report body — so a
	// report recipient can't claim an arbitrary domain. Provide the table + rows.
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS queue_log (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, queue_id bigint NOT NULL, tenant_id bigint NOT NULL, account_id bigint NOT NULL DEFAULT 0, rcpt_to text NOT NULL DEFAULT '', kind text NOT NULL DEFAULT '', payload jsonb NOT NULL DEFAULT '{}', keep_until timestamptz, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE reputation_events RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE queue_log RESTART IDENTITY`); err != nil {
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

	// The authenticated send record: we delivered msgID 42 (tenant 7) to
	// user@sent.example. This — not the report body — determines the domain.
	if _, err := pool.Exec(ctx,
		`INSERT INTO queue_log (queue_id, tenant_id, account_id, rcpt_to, kind) VALUES ($1,$2,0,'user@sent.example','delivered')`,
		msgID, tenantID); err != nil {
		t.Fatal(err)
	}

	countKind := func(kind int) int {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM reputation_events WHERE tenant_id=$1 AND kind=$2`, tenantID, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// --- DSN bounce path: a multipart/report delivery-status. Classified as a
	// bounce (not a complaint) from the body; the affected domain comes from the
	// authenticated send record (sent.example), NOT the DSN's Final-Recipient
	// (which a forger controls). ---
	dsn := []byte("From: mailer-daemon@remote.example\r\nTo: " + verp + "@bounces.example\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"d1\"\r\n\r\n" +
		"--d1\r\nContent-Type: text/plain\r\n\r\n550 user unknown\r\n" +
		"--d1\r\nContent-Type: message/delivery-status\r\n\r\n" +
		"Final-Recipient: rfc822; user@attacker-claimed.example\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--d1--\r\n")
	c, ok, err := svc.IngestReport(ctx, verp, key, dsn)
	if err != nil {
		t.Fatalf("IngestReport(dsn): %v", err)
	}
	if !ok || c.TenantID != tenantID || c.MsgID != msgID || c.Kind != deliverability.KindBounce {
		t.Fatalf("DSN attribution wrong: ok=%v c=%+v", ok, c)
	}
	if c.RemoteDomain != "sent.example" {
		t.Fatalf("DSN domain = %q, want sent.example (authenticated send record, not the report's attacker-claimed domain)", c.RemoteDomain)
	}
	if countKind(deliverability.KindBounce) != 1 {
		t.Fatalf("expected 1 bounce event, got %d", countKind(deliverability.KindBounce))
	}

	// --- ARF complaint path: classified as a complaint from the body; domain again
	// from the authenticated send record, ignoring the report's Original-Rcpt-To.
	// Uses a distinct msgID (43) — ingest is now idempotent per (tenant, msgID), so
	// reusing 42 would dedup against the DSN above. ---
	const arfMsgID = int64(43)
	arfVerp := deliverability.SignedVERPToken(tenantID, arfMsgID, key)
	if _, err := pool.Exec(ctx,
		`INSERT INTO queue_log (queue_id, tenant_id, account_id, rcpt_to, kind) VALUES ($1,$2,0,'user2@sent.example','delivered')`,
		arfMsgID, tenantID); err != nil {
		t.Fatal(err)
	}
	arf := []byte("From: fbl@provider.example\r\nTo: " + arfVerp + "@bounces.example\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: message/feedback-report\r\n\r\n" +
		"Original-Rcpt-To: <victim@attacker-claimed.example>\r\n\r\n" +
		"--b1\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Return-Path: <" + arfVerp + "@bounces.example>\r\nSubject: our mail\r\n\r\nbody\r\n" +
		"--b1--\r\n")
	c2, ok2, err := svc.IngestReport(ctx, arfVerp, key, arf)
	if err != nil {
		t.Fatalf("IngestReport(arf): %v", err)
	}
	if !ok2 || c2.TenantID != tenantID || c2.Kind != deliverability.KindComplaint {
		t.Fatalf("ARF attribution wrong: ok=%v c=%+v", ok2, c2)
	}
	if c2.RemoteDomain != "sent.example" {
		t.Fatalf("ARF domain = %q, want sent.example (authenticated, not report-claimed)", c2.RemoteDomain)
	}
	if countKind(deliverability.KindComplaint) != 1 {
		t.Fatalf("expected 1 complaint event, got %d", countKind(deliverability.KindComplaint))
	}

	// --- Replay: redelivering the SAME signed report (same tenant, msgID) must NOT
	// record another event. Otherwise an attacker who observes a victim's
	// in-the-clear signed VERP bounce address could replay it to drive the victim
	// to auto-pause (cross-tenant reputation DoS via replay). Idempotent per
	// (tenant, msgID) closes it. ---
	for i := 0; i < 5; i++ {
		if _, _, err := svc.IngestReport(ctx, verp, key, dsn); err != nil {
			t.Fatalf("IngestReport(replay dsn): %v", err)
		}
		if _, _, err := svc.IngestReport(ctx, arfVerp, key, arf); err != nil {
			t.Fatalf("IngestReport(replay arf): %v", err)
		}
	}
	if got := countKind(deliverability.KindBounce); got != 1 {
		t.Fatalf("after replays: %d bounce events, want 1 (replay not deduped)", got)
	}
	if got := countKind(deliverability.KindComplaint); got != 1 {
		t.Fatalf("after replays: %d complaint events, want 1 (replay not deduped)", got)
	}

	// --- No send record (aged out / never logged): a valid signed token for a
	// msgID with no queue_log row records the event with an empty domain — safe
	// (can't feed a forged per-domain row) rather than trusting the report body. ---
	const noRecMsg = int64(99)
	verp2 := deliverability.SignedVERPToken(tenantID, noRecMsg, key)
	c3, ok3b, err := svc.IngestReport(ctx, verp2, key, dsn)
	if err != nil {
		t.Fatalf("IngestReport(no-record): %v", err)
	}
	if !ok3b || c3.RemoteDomain != "" {
		t.Fatalf("no-send-record domain = %q, want empty (ok=%v)", c3.RemoteDomain, ok3b)
	}

	// --- Unattributable: a recipient that is not a VERP token → ok=false, no event. ---
	_, ok3, err := svc.IngestReport(ctx, "postmaster", key, []byte("Subject: hi\r\n\r\nx\r\n"))
	if err != nil {
		t.Fatalf("IngestReport(unattributable): %v", err)
	}
	if ok3 {
		t.Fatal("unattributable message was attributed")
	}

	// --- Forged tokens: a 3-part token with a bad MAC AND a 2-part MAC-less token
	// must both fail to authenticate, so no event is attributed to the victim
	// tenant (closes the cross-tenant DoS, including the MAC-drop bypass). ---
	beforeB, beforeC := countKind(deliverability.KindBounce), countKind(deliverability.KindComplaint)
	for _, forged := range []string{"bounces+7.999.aaaaaaaaaaaaaaaa", "bounces+7.999"} {
		_, okF, err := svc.IngestReport(ctx, forged, key, []byte("Subject: failure\r\n\r\n550 nope\r\n"))
		if err != nil {
			t.Fatalf("IngestReport(forged %q): %v", forged, err)
		}
		if okF {
			t.Fatalf("forged VERP token %q accepted — cross-tenant attribution DoS open", forged)
		}
	}
	if countKind(deliverability.KindBounce) != beforeB || countKind(deliverability.KindComplaint) != beforeC {
		t.Fatal("forged token recorded a reputation event")
	}

	t.Logf("OK: DSN/ARF attributed with AUTHENTICATED domain (send record, not report body); no-record→empty; unattributable + forged 3-part/2-part rejected")
}
