// Package junkfilter wraps the junk bayesian filter as a per-account spam
// classifier for octo-mail. Each account has its own filter files (bstore db +
// bloom) under a base directory, so classification and reputation learning are
// per-user — one account's training never leaks into another's.
// Nothing here reimplements the bayesian math; it reuses the junk library.
package junkfilter

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/mjl-/mox/junk"
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

// Manager creates/opens per-account junk filters under BaseDir. Filters are
// cached and guarded by a mutex (the underlying bstore db is single-writer).
type Manager struct {
	BaseDir   string
	Params    junk.Params
	Threshold float64 // probability >= Threshold classifies as junk (e.g. 0.95)

	mu    sync.Mutex
	log   mlog.Log
	cache map[int64]*junk.Filter
}

// NewManager returns a Manager writing filters under baseDir.
func NewManager(baseDir string, params junk.Params, threshold float64) *Manager {
	return &Manager{
		BaseDir:   baseDir,
		Params:    params,
		Threshold: threshold,
		log:       mlog.New("junkfilter", slog.Default()),
		cache:     map[int64]*junk.Filter{},
	}
}

func (m *Manager) paths(accountID int64) (dbPath, bloomPath string) {
	dir := filepath.Join(m.BaseDir, strconv.FormatInt(accountID, 10))
	return filepath.Join(dir, "filter.db"), filepath.Join(dir, "filter.bloom")
}

// filter opens (creating on first use) the account's junk filter.
func (m *Manager) filter(ctx context.Context, accountID int64) (*junk.Filter, error) {
	if f, ok := m.cache[accountID]; ok {
		return f, nil
	}
	dbPath, bloomPath := m.paths(accountID)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o770); err != nil {
		return nil, err
	}
	var f *junk.Filter
	var err error
	if _, statErr := os.Stat(dbPath); statErr == nil {
		f, err = junk.OpenFilter(ctx, m.log, m.Params, dbPath, bloomPath, true)
	} else {
		f, err = junk.NewFilter(ctx, m.log, m.Params, dbPath, bloomPath)
	}
	if err != nil {
		return nil, err
	}
	m.cache[accountID] = f
	return f, nil
}

// Classify returns the spam probability [0,1], whether the classification is
// significant (enough trained words), and whether it exceeds the junk threshold.
func (m *Manager) Classify(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := m.filter(ctx, accountID)
	if err != nil {
		return 0, false, false, err
	}
	res, err := f.ClassifyMessageReader(ctx, byteReaderAt(raw), int64(len(raw)))
	if err != nil {
		return 0, false, false, err
	}
	isJunk = res.Significant && res.Probability >= m.Threshold
	return res.Probability, res.Significant, isJunk, nil
}

// Train adds a message to the account's filter as ham (ham=true) or spam. This
// is the per-account reputation learning: marking a message \Junk trains spam,
// moving out of Junk trains ham.
func (m *Manager) Train(ctx context.Context, accountID int64, ham bool, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := m.filter(ctx, accountID)
	if err != nil {
		return err
	}
	if err := f.TrainMessage(ctx, byteReaderAt(raw), int64(len(raw)), ham); err != nil {
		return err
	}
	return f.Save()
}

// Close flushes and closes all open filters.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for id, f := range m.cache {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.cache, id)
	}
	return firstErr
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
