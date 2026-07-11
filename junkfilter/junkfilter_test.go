package junkfilter_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func openJunkPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres not available (%v)", err)
	}
	// DDL mirrors storage/postgres/schema/09_junkfilter.sql. These tests use a raw
	// pool (not postgres.Open, which applies the full schema and needs a blob store)
	// to stay self-contained — same pattern as the ha tests. Keep in sync with the
	// real schema; a column/index change there must be reflected here or a test
	// could pass against a table shape production never has.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS junk_words (account_id bigint NOT NULL, word text NOT NULL, ham bigint NOT NULL DEFAULT 0, spam bigint NOT NULL DEFAULT 0, PRIMARY KEY (account_id, word))`,
		`CREATE TABLE IF NOT EXISTS junk_totals (account_id bigint NOT NULL PRIMARY KEY, hams bigint NOT NULL DEFAULT 0, spams bigint NOT NULL DEFAULT 0)`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			pool.Close()
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE junk_words, junk_totals`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func spamMsg(i int) []byte {
	return []byte(fmt.Sprintf("From: promo@deals.example\r\nSubject: WINNER buy cheap viagra pills now\r\n\r\n"+
		"Congratulations you WON a FREE prize! Click now to claim cheap meds, cheap loans, cheap watches. Limited offer %d. Act now!!!\r\n", i))
}

func hamMsg(i int) []byte {
	return []byte(fmt.Sprintf("From: alice@work.example\r\nSubject: project sync notes\r\n\r\n"+
		"Hi team, attached are the notes from today's engineering sync. Let's review the migration plan and schedule the deployment for next week. Item %d.\r\n", i))
}

// TestJunkClassifyAndTrainPerAccount proves WF-B: after training an account's
// bayesian filter on ham + spam corpora, a held-out spam message is classified
// as junk and a held-out ham message is not, and that training is per-account —
// an untrained account does not inherit another account's learning. State is in
// Postgres (shared across nodes), not per-node files.
func TestJunkClassifyAndTrainPerAccount(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams, 0.95)
	defer mgr.Close()

	const accA, accB = int64(1), int64(2)

	// Train account A: 60 spam + 60 ham (the filter marks a filter "significant" only
	// once at least 50 ham messages are trained).
	for i := 0; i < 60; i++ {
		if err := mgr.Train(ctx, accA, false, spamMsg(i)); err != nil { // ham=false → spam
			t.Fatalf("train spam %d: %v", i, err)
		}
		if err := mgr.Train(ctx, accA, true, hamMsg(i)); err != nil { // ham=true
			t.Fatalf("train ham %d: %v", i, err)
		}
	}

	// Held-out spam (index beyond training) → classified junk for account A.
	probSpam, sigSpam, isJunkSpam, err := mgr.Classify(ctx, accA, spamMsg(1000))
	if err != nil {
		t.Fatalf("classify spam: %v", err)
	}
	if !sigSpam {
		t.Fatalf("spam classification not significant (prob=%.3f)", probSpam)
	}
	if !isJunkSpam {
		t.Fatalf("held-out spam not classified as junk (prob=%.3f, want >= 0.95)", probSpam)
	}

	// Held-out ham → NOT junk for account A.
	probHam, _, isJunkHam, err := mgr.Classify(ctx, accA, hamMsg(1000))
	if err != nil {
		t.Fatalf("classify ham: %v", err)
	}
	if isJunkHam {
		t.Fatalf("held-out ham misclassified as junk (prob=%.3f)", probHam)
	}
	if probHam >= probSpam {
		t.Fatalf("ham prob %.3f not below spam prob %.3f — filter not discriminating", probHam, probSpam)
	}

	// Per-account isolation: account B was never trained → its classification of
	// the same spam is NOT significant (no learned words leaked from A).
	_, sigB, isJunkB, err := mgr.Classify(ctx, accB, spamMsg(1000))
	if err != nil {
		t.Fatalf("classify B: %v", err)
	}
	if sigB || isJunkB {
		t.Fatalf("untrained account B produced a significant/junk verdict — training leaked across accounts")
	}

	t.Logf("OK: spam prob=%.3f→junk, ham prob=%.3f→not junk (per-account); untrained account B not significant", probSpam, probHam)
}

// TestJunkSharedAcrossNodes proves the #24-7 fix: junk state is shared via
// Postgres, so training performed by one node ("Manager") is visible to another
// node's Manager on the same database. Before the fix (per-node files) node B
// would classify with zero learned words.
func TestJunkSharedAcrossNodes(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()

	nodeA := junkfilter.NewManager(pool, junkfilter.DefaultParams, 0.95)
	nodeB := junkfilter.NewManager(pool, junkfilter.DefaultParams, 0.95)

	const acc = int64(1)
	// Train entirely on node A.
	for i := 0; i < 60; i++ {
		if err := nodeA.Train(ctx, acc, false, spamMsg(i)); err != nil {
			t.Fatalf("nodeA train spam %d: %v", i, err)
		}
		if err := nodeA.Train(ctx, acc, true, hamMsg(i)); err != nil {
			t.Fatalf("nodeA train ham %d: %v", i, err)
		}
	}

	// Classify on node B — it must see node A's training (shared PG state).
	prob, sig, isJunk, err := nodeB.Classify(ctx, acc, spamMsg(1000))
	if err != nil {
		t.Fatalf("nodeB classify: %v", err)
	}
	if !sig {
		t.Fatalf("nodeB classification not significant — training not shared across nodes (prob=%.3f)", prob)
	}
	if !isJunk {
		t.Fatalf("nodeB did not classify held-out spam as junk (prob=%.3f) — shared state broken", prob)
	}
	t.Logf("OK: node B classified spam as junk (prob=%.3f) from node A's training — junk state shared via Postgres", prob)
}

// TestTrainNothingOnNoWords proves the #42 review fix: a message that yields no
// trainable words (empty/wordless body, or a parse failure that tokenize turns
// into an empty word set) must NOT bump junk_totals. A denominator bumped without
// any junk_words rows would skew every other word's spam/ham ratio and drift all
// future classifications for the account. (The bad-Content-Type shortcut folds
// into the same guard; with the non-strict parser used here the reachable trigger
// is the empty-word set.)
func TestTrainNothingOnNoWords(t *testing.T) {
	ctx := context.Background()
	pool := openJunkPool(t, ctx)
	defer pool.Close()
	mgr := junkfilter.NewManager(pool, junkfilter.DefaultParams, 0.95)
	defer mgr.Close()

	const acc = int64(7)
	// A message with no header/body tokens → empty word set (verified via the
	// tokenizer: headers are tokenized too, so this must carry no address/subject).
	noWords := []byte("\r\n\r\n")
	if err := mgr.Train(ctx, acc, false, noWords); err != nil {
		t.Fatalf("train no-words: %v", err)
	}

	// No totals row should have been written (train-nothing).
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_totals WHERE account_id=$1`, acc).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("junk_totals bumped for a no-trainable-words train (rows=%d) — denominator skew", n)
	}
	var w int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM junk_words WHERE account_id=$1`, acc).Scan(&w); err != nil {
		t.Fatal(err)
	}
	if w != 0 {
		t.Fatalf("junk_words written for a no-trainable-words train (rows=%d)", w)
	}
	t.Logf("OK: a no-trainable-words message trains nothing (no denominator skew)")
}
