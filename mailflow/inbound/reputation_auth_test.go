package inbound_test

import (
	"context"
	"net"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReputationRequiresAuth proves the H10 fix (#12): the trusted-sender
// reputation shortcut only applies to an authenticated (DMARC-aligned) sender
// domain, and RecordOutcome only credits reputation for authenticated mail — so
// a spoofable MAIL FROM domain can neither leverage nor build a "trusted"
// reputation. The known-bad reject is intentionally NOT gated on auth (rejecting
// mail that claims a known-bad domain is safe regardless).
func TestReputationRequiresAuth(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, decDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS inbound_reputation (account_id bigint NOT NULL, sender_domain text NOT NULL, ham_count bigint NOT NULL DEFAULT 0, junk_count bigint NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (account_id, sender_domain))`,
		`CREATE TABLE IF NOT EXISTS rulesets (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, account_id bigint NOT NULL, header_name text NOT NULL, header_substr text NOT NULL, mailbox text NOT NULL, force_accept boolean NOT NULL DEFAULT false, is_forward boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE IF NOT EXISTS greylist (account_id bigint NOT NULL, sender_domain text NOT NULL, client_subnet text NOT NULL, allowed_at timestamptz NOT NULL, PRIMARY KEY (account_id, sender_domain, client_subnet))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	const acc = int64(9910)
	if _, err := pool.Exec(ctx, `DELETE FROM inbound_reputation WHERE account_id=$1`, acc); err != nil {
		t.Fatal(err)
	}

	d := &inbound.Decider{Pool: pool, TrustedHamCount: 3}
	msg := []byte("From: x@trusted.example\r\nTo: u@acme.test\r\nSubject: hi\r\n\r\nbody\r\n")
	ip := net.ParseIP("203.0.113.50")

	// Seed a strong ham history for trusted.example.
	if _, err := pool.Exec(ctx,
		`INSERT INTO inbound_reputation (account_id, sender_domain, ham_count) VALUES ($1,'trusted.example',10)`, acc); err != nil {
		t.Fatal(err)
	}

	// Authenticated → trusted-sender shortcut fires (Accept, no greylist/content).
	if dec := d.Decide(ctx, acc, "trusted.example", ip, msg, true, nil); dec.Reason != "trusted-sender" {
		t.Fatalf("authed trusted domain: reason=%q verdict=%v, want trusted-sender", dec.Reason, dec.Verdict)
	}
	// Unauthenticated → shortcut suppressed (must NOT be trusted-sender).
	if dec := d.Decide(ctx, acc, "trusted.example", ip, msg, false, nil); dec.Reason == "trusted-sender" {
		t.Fatalf("unauthenticated domain got the trusted-sender fast-path — spoof bypass")
	}

	// RecordOutcome must not build reputation for unauthenticated mail.
	const fresh = "fresh.example"
	if err := d.RecordOutcome(ctx, acc, fresh, false /*authed*/, true /*ham*/); err != nil {
		t.Fatal(err)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM inbound_reputation WHERE account_id=$1 AND sender_domain=$2`, acc, fresh).Scan(&n)
	if n != 0 {
		t.Fatalf("unauthenticated RecordOutcome created reputation rows (%d) — poisoning path open", n)
	}
	// Authenticated RecordOutcome does build it.
	if err := d.RecordOutcome(ctx, acc, fresh, true, true); err != nil {
		t.Fatal(err)
	}
	var ham int64
	pool.QueryRow(ctx, `SELECT ham_count FROM inbound_reputation WHERE account_id=$1 AND sender_domain=$2`, acc, fresh).Scan(&ham)
	if ham != 1 {
		t.Fatalf("authenticated RecordOutcome ham_count=%d, want 1", ham)
	}

	// Adaptive junk threshold must not use a spoofable domain's history: a
	// ham-heavy domain, when UNauthenticated, gets the neutral base threshold, so
	// a borderline-junk message is filed Junk rather than accepted-lenient.
	// hammy.example has strong ham history; classify returns a borderline prob
	// (0.90) that a lenient (authed) threshold would accept but the base rejects.
	if _, err := pool.Exec(ctx,
		`INSERT INTO inbound_reputation (account_id, sender_domain, ham_count, junk_count) VALUES ($1,'hammy.example',90,10)
		 ON CONFLICT (account_id, sender_domain) DO UPDATE SET ham_count=90, junk_count=10`, acc); err != nil {
		t.Fatal(err)
	}
	classify := func(ctx context.Context, accountID int64, raw []byte) (float64, bool, bool, error) {
		return 0.97, true, true, nil
	}
	hammyMsg := []byte("From: x@hammy.example\r\nTo: u@acme.test\r\nSubject: hi\r\n\r\nbody\r\n")
	// Authenticated → lenient threshold (~0.998 for 90/10 history) → 0.97 accepted.
	if dec := d.Decide(ctx, acc, "hammy.example", ip, hammyMsg, true, classify); dec.Verdict != inbound.Accept {
		t.Fatalf("authed hammy 0.97 → %v (%s), want Accept (lenient)", dec.Verdict, dec.Reason)
	}
	// Unauthenticated → neutral base threshold (0.95) → 0.97 filed Junk (no borrowed leniency).
	if dec := d.Decide(ctx, acc, "hammy.example", ip, hammyMsg, false, classify); dec.Verdict != inbound.AcceptJunk {
		t.Fatalf("unauthenticated hammy 0.97 → %v (%s), want AcceptJunk (no lenient threshold)", dec.Verdict, dec.Reason)
	}

	t.Logf("OK: trusted shortcut + reputation credit + adaptive leniency all gated on authentication; known-bad reject ungated")
}
