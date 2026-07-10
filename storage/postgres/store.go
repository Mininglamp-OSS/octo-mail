// Package postgres implements the kernel store interfaces (core/store) on
// PostgreSQL + a blob store. It is the change-log kernel: writes append immutable
// per-account Change entries and update projections in the same transaction,
// serialized per account by a transaction-scoped advisory lock so ordering holds
// across stateless nodes.
package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// schemaFS holds the DDL split by concern (see schema/*.sql). Files are applied
// in filename order — the NN_ prefixes encode dependency order, and the split
// makes the architecture legible: 02_changelog is the ★真源 (append-only spine),
// 03_projections are the rebuildable folds, the rest are subsystem tables.
//
//go:embed schema/*.sql
var schemaFS embed.FS

// schemaDDL concatenates the embedded schema files in filename order. fs.ReadDir
// returns entries sorted by name, so the NN_ prefixes give dependency order.
func schemaDDL() (string, error) {
	entries, err := fs.ReadDir(schemaFS, "schema")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := schemaFS.ReadFile("schema/" + e.Name())
		if err != nil {
			return "", err
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Store is the top-level handle: a Postgres pool plus a blob store for bodies.
// It opens per-account handles (kernel/store.Account) via the directory.
type Store struct {
	Pool *pgxpool.Pool
	Blob blob.Store

	mu           sync.Mutex
	subs         map[int64][]*subscriber
	coordEnabled atomic.Bool
}

// subscriber is a local change-stream subscriber (IMAP IDLE / JMAP push) plus
// the highest change-log seq it has been delivered — so cross-node replay never
// re-delivers what the in-process publish already sent.
type subscriber struct {
	comm    *store.Comm
	mu      sync.Mutex
	lastSeq store.ModSeq
}

func (s *subscriber) seen() store.ModSeq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

func (s *subscriber) advance(seq store.ModSeq) {
	s.mu.Lock()
	if seq > s.lastSeq {
		s.lastSeq = seq
	}
	s.mu.Unlock()
}

// Open connects to Postgres, applies the schema, and returns a Store.
func Open(ctx context.Context, dsn string, bs blob.Store) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres dsn: %w", err)
	}
	// Detect dead connections promptly. Without this, a partitioned leadership
	// connection relies on OS TCP defaults (often minutes) before it notices the
	// backend is gone — widening the leader-election handoff window. A short
	// TCP keepalive plus periodic pool health checks bound that detection to
	// seconds; the authoritative liveness signal is still the advisory lock
	// (see ops/ha.Leader.IsLeader), this just makes the client side timely.
	cfg.ConnConfig.RuntimeParams["tcp_keepalives_idle"] = "10"
	cfg.ConnConfig.RuntimeParams["tcp_keepalives_interval"] = "5"
	cfg.ConnConfig.RuntimeParams["tcp_keepalives_count"] = "3"
	cfg.HealthCheckPeriod = 15 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	ddl, err := schemaDDL()
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("loading schema: %w", err)
	}
	// Serialize bootstrap across nodes with a session advisory lock so concurrent
	// startups can't race the same CREATE INDEX/TABLE (which is not internally
	// serialized and can deadlock or error under contention). The key is a fixed
	// namespace distinct from the per-account (account id) and leader-election keys.
	// Held on one dedicated connection for the DDL Exec, then released; the schema
	// DDL itself is idempotent (IF NOT EXISTS), so the lock only prevents the
	// concurrent-DDL race, not re-application.
	const schemaBootstrapKey = int64(0x6f6d5f7363686d) // "om_schm"
	conn, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("acquiring bootstrap conn: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, schemaBootstrapKey); err != nil {
		conn.Release()
		pool.Close()
		return nil, fmt.Errorf("bootstrap advisory lock: %w", err)
	}
	_, ddlErr := conn.Exec(ctx, ddl)
	// Release the lock on the same connection before returning it to the pool.
	_, unlockErr := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, schemaBootstrapKey)
	conn.Release()
	if ddlErr != nil {
		pool.Close()
		return nil, fmt.Errorf("applying schema: %w", ddlErr)
	}
	if unlockErr != nil {
		pool.Close()
		return nil, fmt.Errorf("bootstrap advisory unlock: %w", unlockErr)
	}
	return &Store{Pool: pool, Blob: bs}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s.Pool != nil {
		s.Pool.Close()
	}
}

// publish fans committed changes to local subscribers (in-process, rich
// []Change) and rings the cross-node doorbell (pg_notify) so other nodes replay.
// Local subscribers' lastSeq is advanced here so the coordinator's replay path
// won't re-deliver the same changes on this node.
func (s *Store) publish(ctx context.Context, accountID int64, changes []store.Change, head store.ModSeq) {
	s.mu.Lock()
	subs := append([]*subscriber(nil), s.subs[accountID]...)
	s.mu.Unlock()
	for _, sub := range subs {
		select {
		case sub.comm.Changes <- changes:
			sub.advance(head)
		default: // slow consumer; drop — it resyncs from the log by offset
		}
	}
	s.emitNotify(ctx, accountID, int64(head))
}

func (s *Store) registerComm(accountID int64) *store.Comm {
	sub := &subscriber{}
	comm := store.NewComm(accountID, 256, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		list := s.subs[accountID]
		for i, x := range list {
			if x == sub {
				s.subs[accountID] = append(list[:i], list[i+1:]...)
				break
			}
		}
	})
	sub.comm = comm
	// New subscriber starts at the current head, so it only receives changes
	// that happen after it subscribed (avoids replaying full history on connect).
	if head, err := s.headOf(accountID); err == nil {
		sub.lastSeq = head
	}
	s.mu.Lock()
	if s.subs == nil {
		s.subs = map[int64][]*subscriber{}
	}
	s.subs[accountID] = append(s.subs[accountID], sub)
	s.mu.Unlock()
	return comm
}

func (s *Store) headOf(accountID int64) (store.ModSeq, error) {
	var head int64
	err := s.Pool.QueryRow(context.Background(), `SELECT changelog_seq FROM accounts WHERE id=$1`, accountID).Scan(&head)
	return store.ModSeq(head), err
}
