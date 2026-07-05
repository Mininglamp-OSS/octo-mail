package inbound_test

import (
	"context"
	"net"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/jackc/pgx/v5/pgxpool"
)

const decDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestAdaptiveThresholdAndForwarded proves two the analyze heuristics on the
// Decider directly (real PG for rulesets/reputation, synthetic classifier for a
// deterministic spam probability):
//   - adaptive junk threshold: a sender domain with strong ham history gets a
//     more lenient threshold, so a borderline-junk message it sends is accepted,
//     while the same probability from a no-history domain is filed as Junk.
//   - forwarded handling: an is_forward ruleset match bypasses reputation/content
//     rejection even for an otherwise known-bad sender.
func TestAdaptiveThresholdAndForwarded(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, decDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	// Minimal schema (rulesets + inbound_reputation) for an isolated run.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS inbound_reputation (account_id bigint NOT NULL, sender_domain text NOT NULL, ham_count bigint NOT NULL DEFAULT 0, junk_count bigint NOT NULL DEFAULT 0, PRIMARY KEY (account_id, sender_domain))`,
		`CREATE TABLE IF NOT EXISTS rulesets (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, account_id bigint NOT NULL, header_name text NOT NULL, header_substr text NOT NULL, mailbox text NOT NULL, force_accept boolean NOT NULL DEFAULT true, is_forward boolean NOT NULL DEFAULT false, ord int NOT NULL DEFAULT 0)`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE inbound_reputation, rulesets`); err != nil {
		t.Fatal(err)
	}

	const acc = int64(9001)
	// A classifier that always returns prob=0.90, significant. Base junk threshold
	// is 0.95, so 0.90 is normally NOT junk. But with adaptive lowering for a
	// junk-heavy domain, the effective threshold drops below 0.90 → filed Junk.
	classify := func(ctx context.Context, accountID int64, raw []byte) (float64, bool, bool, error) {
		return 0.90, true, true, nil
	}

	d := &inbound.Decider{Pool: pool}

	msg := []byte("From: x@example.org\r\nTo: u1@example.com\r\nSubject: hi\r\n\r\nbody\r\n")

	// Domain with strong ham history → lenient threshold → 0.90 accepted to Inbox.
	if _, err := pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, ham_count, junk_count) VALUES ($1,'hammy.example',90,10)`, acc); err != nil {
		t.Fatal(err)
	}
	decHam := d.Decide(ctx, acc, "hammy.example", net.ParseIP("203.0.113.1"), msg, classify)
	if decHam.Verdict != inbound.Accept {
		t.Fatalf("hammy domain 0.90 → %v (%s), want Accept (adaptive lenient)", decHam.Verdict, decHam.Reason)
	}

	// Domain with junk-heavy history → stricter threshold → 0.90 filed as Junk.
	if _, err := pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, ham_count, junk_count) VALUES ($1,'junky.example',10,90)`, acc); err != nil {
		t.Fatal(err)
	}
	decJunk := d.Decide(ctx, acc, "junky.example", net.ParseIP("203.0.113.2"), msg, classify)
	if decJunk.Verdict != inbound.AcceptJunk {
		t.Fatalf("junky domain 0.90 → %v (%s), want AcceptJunk (adaptive strict)", decJunk.Verdict, decJunk.Reason)
	}

	// Forwarded handling: a known-bad sender that would be Rejected, but an
	// is_forward ruleset matching its List-Id/forwarding header bypasses rejection.
	if _, err := pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, junk_count) VALUES ($1,'fwd.example',5)`, acc); err != nil {
		t.Fatal(err)
	}
	// Without a ruleset: known-bad → Reject.
	badMsg := []byte("From: relay@fwd.example\r\nTo: u1@example.com\r\nX-Forwarded-For-Account: u1\r\nSubject: fwd\r\n\r\nx\r\n")
	if dec := d.Decide(ctx, acc, "fwd.example", net.ParseIP("203.0.113.3"), badMsg, classify); dec.Verdict != inbound.Reject {
		t.Fatalf("known-bad fwd.example without ruleset → %v, want Reject", dec.Verdict)
	}
	// With an is_forward ruleset matching the forwarding header → Accept to Forwarded.
	if _, err := pool.Exec(ctx,
		`INSERT INTO rulesets (account_id, header_name, header_substr, mailbox, force_accept, is_forward) VALUES ($1,'X-Forwarded-For-Account','u1','Forwarded',false,true)`, acc); err != nil {
		t.Fatal(err)
	}
	decFwd := d.Decide(ctx, acc, "fwd.example", net.ParseIP("203.0.113.3"), badMsg, classify)
	if decFwd.Verdict != inbound.Accept {
		t.Fatalf("forwarded message → %v (%s), want Accept (bypass reputation reject)", decFwd.Verdict, decFwd.Reason)
	}
	if decFwd.Mailbox != "Forwarded" {
		t.Fatalf("forwarded message mailbox = %q, want Forwarded", decFwd.Mailbox)
	}

	t.Logf("OK: adaptive threshold (hammy 0.90→Inbox, junky 0.90→Junk); forwarded ruleset bypassed known-bad reject → Forwarded")
}
