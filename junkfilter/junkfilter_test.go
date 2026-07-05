package junkfilter_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
)

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
// an untrained account does not inherit another account's learning.
func TestJunkClassifyAndTrainPerAccount(t *testing.T) {
	ctx := context.Background()
	mgr := junkfilter.NewManager(t.TempDir(), junkfilter.DefaultParams, 0.95)
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
