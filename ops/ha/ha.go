// Package ha provides the single-active-leader primitive used to make a set of
// otherwise-stateless octo-mail nodes elect exactly one leader for cluster-wide
// singleton work (report scheduling, cron-style projection drains, warmup
// counter resets). It uses a PostgreSQL session-level advisory lock: at most one
// session can hold a given lock key, and the lock is released automatically when
// that session's connection drops — which is exactly the fencing behavior a
// crashed leader needs (no lease timers, no split brain within one PG).
//
// This is the election/fencing core that an orchestrator like Patroni layers
// automation around; the daemon is external, but the guarantee (one live leader,
// automatic handoff on crash) is real and tested here against real PostgreSQL.
package ha

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Leader campaigns for and holds leadership on a lock key. It keeps a dedicated
// connection for the duration of leadership; releasing it (or losing it on
// crash) frees the advisory lock so another node can take over.
type Leader struct {
	pool *pgxpool.Pool
	key  int64
	conn *pgxpool.Conn // held while leader; nil when not leader
	pid  int32         // backend PID of the held connection (for diagnostics/tests)
}

// New creates a Leader for the given advisory-lock key (any process using the
// same key contends for the same leadership).
func New(pool *pgxpool.Pool, key int64) *Leader {
	return &Leader{pool: pool, key: key}
}

// TryAcquire attempts to become leader without blocking. Returns true if this
// node is now the leader. Idempotent: calling it again while already leader
// returns true. On success a dedicated connection is checked out and held.
func (l *Leader) TryAcquire(ctx context.Context) (bool, error) {
	if l.conn != nil {
		return true, nil // already leader
	}
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&ok); err != nil {
		conn.Release()
		return false, err
	}
	if !ok {
		conn.Release()
		return false, nil
	}
	l.conn = conn
	_ = conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&l.pid)
	return true, nil
}

// BackendPID returns the PostgreSQL backend PID holding the leadership lock, or
// 0 when not leader. Exposed so operators/tests can observe or terminate it.
func (l *Leader) BackendPID() int32 { return l.pid }

// IsLeader reports whether this node currently holds leadership. It verifies the
// held connection is still alive (a dropped connection means leadership was lost).
func (l *Leader) IsLeader(ctx context.Context) bool {
	if l.conn == nil {
		return false
	}
	if err := l.conn.Ping(ctx); err != nil {
		l.conn.Release()
		l.conn = nil
		return false
	}
	return true
}

// Resign releases leadership: unlocks the advisory lock and returns the
// connection to the pool, letting a standby acquire leadership.
func (l *Leader) Resign(ctx context.Context) error {
	if l.conn == nil {
		return nil
	}
	_, err := l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key)
	l.conn.Release()
	l.conn = nil
	if err != nil {
		return fmt.Errorf("advisory unlock: %w", err)
	}
	return nil
}
