package deliverability_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/jackc/pgx/v5/pgxpool"
)

// arfReport builds a minimal but real RFC 5965 ARF complaint whose embedded
// original message has a VERP return-path bounces+<tenant>.<msg>@bounce.example.
func arfReport(tenantID, msgID int64, rcptDomain string) []byte {
	verp := deliverability.VERPToken(tenantID, msgID)
	body := "" +
		"From: complaints@" + rcptDomain + "\r\n" +
		"To: fbl@bounce.example\r\n" +
		"Subject: complaint\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"bound42\"\r\n" +
		"\r\n" +
		"--bound42\r\n" +
		"Content-Type: text/plain\r\n\r\nThis is an abuse report.\r\n" +
		"--bound42\r\n" +
		"Content-Type: message/feedback-report\r\n\r\n" +
		"Feedback-Type: abuse\r\n" +
		"User-Agent: MailProvider/1.0\r\n" +
		"Original-Rcpt-To: <victim@" + rcptDomain + ">\r\n" +
		"\r\n" +
		"--bound42\r\n" +
		"Content-Type: message/rfc822\r\n\r\n" +
		"Return-Path: <" + verp + "@bounce.example>\r\n" +
		"From: news@sender.example\r\n" +
		"To: victim@" + rcptDomain + "\r\n" +
		"Subject: our newsletter\r\n\r\nbody\r\n" +
		"--bound42--\r\n"
	return []byte(body)
}

// TestFBLAttributionAndIsolation proves ARF/FBL parsing attributes complaints to
// the exact sending tenant via the VERP return-path, and that pausing is
// per-tenant: enough complaints against tenant A pause A for the complaining
// domain, while tenant B (same domain) is untouched.
func TestFBLAttributionAndIsolation(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dkimDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS reputation_events (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, account_id bigint, kind smallint NOT NULL, remote_domain text NOT NULL, ip_id bigint, at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS reputation_score (tenant_id bigint NOT NULL, remote_domain text NOT NULL, sent bigint NOT NULL DEFAULT 0, complaints bigint NOT NULL DEFAULT 0, bounces bigint NOT NULL DEFAULT 0, paused boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, remote_domain))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE reputation_events, reputation_score RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	const tenantA, tenantB = int64(1), int64(2)
	const domain = "gmail.com"
	svc := &deliverability.Service{Pool: pool}

	// Ensure the two tenants exist (reputation_score has an FK to tenants in the
	// canonical schema). Use fixed ids via explicit inserts, tolerating reuse.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS tenants (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, quota_bytes bigint, kms_key_id text, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (name) VALUES ('a'),('b')`); err != nil {
		t.Fatal(err)
	}

	// Both tenants have sent plenty to gmail.com (past the min sample).
	for _, tid := range []int64{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO reputation_score (tenant_id, remote_domain, sent) VALUES ($1,$2,1000)`, tid, domain); err != nil {
			t.Fatal(err)
		}
	}

	// Feed 20 ARF complaints attributed (via VERP) to tenant A only.
	for i := 0; i < 20; i++ {
		raw := arfReport(tenantA, int64(1000+i), domain)
		c, err := svc.RecordComplaint(ctx, raw)
		if err != nil {
			t.Fatalf("record complaint %d: %v", i, err)
		}
		if c.TenantID != tenantA {
			t.Fatalf("complaint attributed to tenant %d, want A=%d", c.TenantID, tenantA)
		}
		if c.RemoteDomain != domain {
			t.Fatalf("complaint domain = %q, want %q", c.RemoteDomain, domain)
		}
	}

	// Tenant A must now be paused for gmail.com (complaint rate 20/1000=2% > 1%).
	pausedA := isPaused(t, pool, tenantA, domain)
	if !pausedA {
		t.Fatalf("tenant A not paused after 20 complaints — FBL not driving reputation")
	}
	// Tenant B, same domain, must be UNAFFECTED (isolation).
	if isPaused(t, pool, tenantB, domain) {
		t.Fatalf("tenant B paused by tenant A's complaints — cross-tenant reputation leak")
	}

	// A garbage report without a VERP token is rejected, never attributed.
	if _, err := svc.RecordComplaint(ctx, []byte("Subject: not an arf\r\n\r\nnope\r\n")); err == nil {
		t.Fatalf("non-ARF message was accepted as a complaint")
	}

	t.Logf("OK: 20 ARF complaints attributed to tenant A via VERP → A paused for %s; tenant B unaffected (per-tenant FBL isolation)", domain)
}

func isPaused(t *testing.T, pool *pgxpool.Pool, tenantID int64, domain string) bool {
	t.Helper()
	var paused bool
	if err := pool.QueryRow(context.Background(),
		`SELECT paused FROM reputation_score WHERE tenant_id=$1 AND remote_domain=$2`,
		tenantID, domain).Scan(&paused); err != nil {
		t.Fatal(fmt.Errorf("query paused: %w", err))
	}
	return paused
}
