// Package junkfilter is octo-mail's per-account bayesian spam classifier. Each
// account has its own learned word statistics — one account's training never
// leaks into another's — but unlike a file-backed filter, the statistics live in
// PostgreSQL (junk_words / junk_totals), SHARED across all nodes. That matters
// for the stateless-node model: training a message as spam on one node must
// affect classification on every node, and there must not be N divergent local
// filters. The message tokenizer is reused verbatim from the junk library (no
// reimplementation of parsing/n-grams); only the storage and the bayesian
// combination are reimplemented over SQL.
package junkfilter

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
)

// DefaultParams mirror the localserve defaults: single words, gentle power,
// top-10 words, ignore near-neutral, rare-word threshold 2.
var DefaultParams = junk.Params{
	Onegrams:    true,
	MaxPower:    0.01,
	TopWords:    10,
	IgnoreWords: 0.1,
	RareWords:   2,
}

// significantHamMin mirrors the junk library: a classification is only
// "significant" once the account has trained at least this many ham messages, so
// a handful of spam signals can't over-eagerly reject before there's ham signal.
const significantHamMin = 50

// Manager classifies and trains per-account junk filters backed by Postgres. It
// is safe for concurrent use (PostgreSQL serializes the upserts); there is no
// per-node cache or single-writer lock — the database IS the shared state.
type Manager struct {
	Pool      *pgxpool.Pool
	Params    junk.Params
	Threshold float64 // probability >= Threshold classifies as junk (e.g. 0.95)

	log mlog.Log
}

// NewManager returns a Manager storing per-account word statistics in Postgres.
func NewManager(pool *pgxpool.Pool, params junk.Params, threshold float64) *Manager {
	return &Manager{
		Pool:      pool,
		Params:    params,
		Threshold: threshold,
		log:       mlog.New("junkfilter", slog.Default()),
	}
}

// tokenize extracts the message's word set using the junk library's tokenizer
// (headers + text/html parts, n-grams per Params). The tokenizer reads only the
// Params, not any database/bloom state, so a params-only Filter value suffices.
// badContentType reports the junk-library signal that the message's Content-Type
// is malformed — a strong spam indicator the caller treats as certain-spam.
func (m *Manager) tokenize(raw []byte) (words map[string]struct{}, badContentType bool, err error) {
	f := &junk.Filter{Params: m.Params}
	part, perr := message.EnsurePart(m.log.Logger, false, bytes.NewReader(raw), int64(len(raw)))
	if perr != nil && errors.Is(perr, message.ErrBadContentType) {
		// Mirror the junk library: a bad content-type is a sure sign of spam.
		return nil, true, nil
	}
	// For any other parse trouble, EnsurePart still returns a best-effort Part;
	// tokenize what we can (an unreadable message simply yields few/no words).
	w, terr := f.ParseMessage(part)
	if terr != nil {
		return map[string]struct{}{}, false, nil
	}
	return w, false, nil
}

// Classify returns the spam probability [0,1], whether the classification is
// significant (enough trained ham), and whether it exceeds the junk threshold.
func (m *Manager) Classify(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error) {
	words, badCT, err := m.tokenize(raw)
	if err != nil {
		return 0, false, false, err
	}
	if badCT {
		return 1, true, true, nil
	}

	var hams, spams int64
	err = m.Pool.QueryRow(ctx,
		`SELECT hams, spams FROM junk_totals WHERE account_id=$1`, accountID).Scan(&hams, &spams)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Untrained account: no signal. Probability 0.5 is neutral; not significant.
			return 0.5, false, false, nil
		}
		return 0, false, false, err
	}

	// Load the (ham, spam) counts for exactly the message's words in one round-trip.
	wl := make([]string, 0, len(words))
	for w := range words {
		wl = append(wl, w)
	}
	counts := map[string]struct{ ham, spam int64 }{}
	if len(wl) > 0 {
		rows, e := m.Pool.Query(ctx,
			`SELECT word, ham, spam FROM junk_words WHERE account_id=$1 AND word = ANY($2)`, accountID, wl)
		if e != nil {
			return 0, false, false, e
		}
		for rows.Next() {
			var w string
			var h, sp int64
			if e := rows.Scan(&w, &h, &sp); e != nil {
				rows.Close()
				return 0, false, false, e
			}
			counts[w] = struct{ ham, spam int64 }{h, sp}
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			return 0, false, false, e
		}
	}

	prob = m.probability(words, counts, hams, spams)
	significant = hams >= significantHamMin
	isJunk = significant && prob >= m.Threshold
	return prob, significant, isJunk, nil
}

// wordScore is a per-word spaminess used for the top-N selection.
type wordScore struct {
	word  string
	score float64
}

// probability ports the junk library's bayesian combination verbatim (see
// junk.Filter.ClassifyWords): per-word spaminess r = (spam/spams)/(spam/spams +
// ham/hams), clamped to [MaxPower, 1-MaxPower], with rare-word power reduction and
// near-neutral (IgnoreWords) skipping; the TopWords most hammy and spammy are
// combined via log-odds into a final probability.
func (m *Manager) probability(words map[string]struct{}, counts map[string]struct{ ham, spam int64 }, hams, spams int64) float64 {
	p := m.Params
	var hamHigh float64 = 0
	var spamLow float64 = 1
	var topHam, topSpam []wordScore

	for w := range words {
		c, ok := counts[w]
		if !ok {
			continue
		}
		var wS, wH float64
		if spams > 0 {
			wS = float64(c.spam) / float64(spams)
		}
		if hams > 0 {
			wH = float64(c.ham) / float64(hams)
		}
		if wS+wH == 0 {
			continue
		}
		r := wS / (wS + wH)
		if r < p.MaxPower {
			r = p.MaxPower
		} else if r >= 1-p.MaxPower {
			r = 1 - p.MaxPower
		}
		if c.ham+c.spam <= int64(p.RareWords) {
			r += float64(1+int64(p.RareWords)-(c.ham+c.spam)) * (0.5 - r) / 10
		}
		if math.Abs(0.5-r) < p.IgnoreWords {
			continue
		}
		if r < 0.5 {
			if len(topHam) >= p.TopWords && r > hamHigh {
				continue
			}
			topHam = append(topHam, wordScore{w, r})
			if r > hamHigh {
				hamHigh = r
			}
		} else if r > 0.5 {
			if len(topSpam) >= p.TopWords && r < spamLow {
				continue
			}
			topSpam = append(topSpam, wordScore{w, r})
			if r < spamLow {
				spamLow = r
			}
		}
	}

	sort.Slice(topHam, func(i, j int) bool {
		a, b := topHam[i], topHam[j]
		if a.score == b.score {
			return len(a.word) > len(b.word)
		}
		return a.score < b.score
	})
	sort.Slice(topSpam, func(i, j int) bool {
		a, b := topSpam[i], topSpam[j]
		if a.score == b.score {
			return len(a.word) > len(b.word)
		}
		return a.score > b.score
	})
	if len(topHam) > p.TopWords {
		topHam = topHam[:p.TopWords]
	}
	if len(topSpam) > p.TopWords {
		topSpam = topSpam[:p.TopWords]
	}

	var eta float64
	for _, x := range topHam {
		eta += math.Log(1-x.score) - math.Log(x.score)
	}
	for _, x := range topSpam {
		eta += math.Log(1-x.score) - math.Log(x.score)
	}
	return 1 / (1 + math.Pow(math.E, eta))
}

// Train adds a message to the account's filter as ham or spam: it tokenizes the
// message and, in one transaction, bumps the matching per-word counter and the
// account's ham/spam total. Marking a message \Junk trains spam; moving it out of
// Junk trains ham.
func (m *Manager) Train(ctx context.Context, accountID int64, ham bool, raw []byte) error {
	words, _, err := m.tokenize(raw)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		hamDelta, spamDelta := 0, 1
		if ham {
			hamDelta, spamDelta = 1, 0
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO junk_totals (account_id, hams, spams) VALUES ($1,$2,$3)
			 ON CONFLICT (account_id) DO UPDATE SET hams = junk_totals.hams + $2, spams = junk_totals.spams + $3`,
			accountID, hamDelta, spamDelta); err != nil {
			return err
		}
		if len(words) == 0 {
			return nil
		}
		// Bulk-upsert every word's counter in ONE round trip via unnest, instead of
		// an Exec per token (a token-heavy message would otherwise be hundreds of
		// SQL round trips per train). The per-word delta is uniform for this message
		// (hamDelta/spamDelta), so it is applied to each unnested word.
		wl := make([]string, 0, len(words))
		for w := range words {
			wl = append(wl, w)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO junk_words (account_id, word, ham, spam)
			 SELECT $1, w, $3, $4 FROM unnest($2::text[]) AS w
			 ON CONFLICT (account_id, word) DO UPDATE SET ham = junk_words.ham + $3, spam = junk_words.spam + $4`,
			accountID, wl, hamDelta, spamDelta); err != nil {
			return err
		}
		return nil
	})
}

// Close is a no-op: there is no per-node state to flush (the database owns it).
// Retained so existing call sites (defer mgr.Close()) keep working.
func (m *Manager) Close() error { return nil }
