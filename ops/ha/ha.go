// Package ha provides the single-active-leader primitive used to make a set of
// otherwise-stateless octo-mail nodes elect exactly one leader for cluster-wide
// singleton work (report scheduling, cron-style projection drains, warmup
// counter resets).
//
// Leadership rests on THREE mechanisms, each closing a gap the others leave:
//
//   - A session-level PostgreSQL advisory lock (pg_advisory_lock) is the election
//     and the same-primary mutual exclusion: at most one session holds a given key,
//     and the lock is released automatically when that session's connection drops
//     — exactly the fast, timer-free fencing a crashed leader needs WITHIN one
//     PostgreSQL. Same-primary crash failover is immediate (no lease to age out).
//
//   - A replicated leader-lease row (leader_lease, schema/08) carrying an `epoch`
//     bumped on every acquisition. Unlike the advisory lock, the lease is
//     ordinary table data: it lives in the WAL and is visible identically on an old
//     primary and a promoted replica. Its purpose is the PG FAILOVER case the
//     advisory lock cannot cover — the lock is primary-local and NOT replicated, so
//     after a promotion the two nodes have independent lock namespaces and the lock
//     alone can't tell a demoted old primary from the new one. The lease provides
//     two things across that boundary: (a) the heartbeat is a WRITE, so a leader
//     whose primary was demoted to a read-only replica fails its next heartbeat and
//     steps down (see Heartbeat); (b) the epoch is a fencing token for
//     non-idempotent work (see FenceExec) — a new leader bumps it, so an old
//     leader's in-flight write, guarded by its now-stale epoch, is rejected.
//     Fencing is by (holder, epoch) IDENTITY, not epoch ordering: a clean Resign
//     deletes the row so the next acquisition restarts at epoch 1, which is safe
//     because distinct live leaders carry distinct holders. The epoch is thus
//     distinct-per-tenure, not globally monotonic.
//
//   - A pg_is_in_recovery() gate: a replica never acquires leadership, so a node
//     behind a promotion boundary refuses the campaign until it is itself a primary.
//
// This is the election/fencing core that an orchestrator like Patroni/repmgr layers
// automation around. It assumes that orchestrator's normal contract — a failed-over
// old primary is demoted (read-only) or fenced, not left writable alongside the new
// one. Under that contract the guarantee (one live leader, immediate same-primary
// handoff on crash, step-down + epoch fence across promotion) is real and tested
// here against real PostgreSQL. A true two-writable-primaries split is a
// storage-layer failure this primitive cannot paper over (the two would have
// divergent WAL); preventing it is the promotion daemon's job.
package ha

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrFenced is returned by FenceExec when the lease is no longer held at the held
// epoch — i.e. this node has been fenced out and must not perform the write.
var ErrFenced = errors.New("ha: leadership fenced (lease lost or epoch superseded)")

// Leader campaigns for and holds leadership on a lock key. It keeps a dedicated
// connection for the duration of leadership; releasing it (or losing it on
// crash) frees the advisory lock so another node can take over. While leader it
// also owns a lease row stamped with an epoch that fences its writes across a
// PostgreSQL promotion.
//
// Concurrency: the campaign loop (Coordinator.Run's goroutine) is the sole
// caller of TryAcquire/IsLeader/Heartbeat/Resign and the sole mutator of `conn`.
// The `epoch`/`pid` fields are also read by Epoch/BackendPID and FenceExec, which
// a leader-work goroutine may call, so those fields are guarded by `mu`. FenceExec
// deliberately does NOT touch `conn` (it borrows a fresh pooled connection) — a
// pgx connection is not safe for concurrent use, and sharing the leadership
// connection with a work goroutine would corrupt its protocol stream.
type Leader struct {
	pool   *pgxpool.Pool
	key    int64
	nodeID string        // identity written to leader_lease.holder
	conn   *pgxpool.Conn // held while leader; nil when not leader (campaign goroutine only)
	mu     sync.Mutex    // guards pid, epoch (read cross-goroutine by BackendPID/Epoch/FenceExec)
	pid    int32         // backend PID of the held connection (for diagnostics/tests)
	epoch  int64         // fencing token of the currently held lease; 0 when not leader
}

// New creates a Leader for the given advisory-lock key (any process using the
// same key contends for the same leadership). nodeID identifies this node in the
// lease row; it should be stable per process (e.g. cfg.nodeID).
func New(pool *pgxpool.Pool, key int64, nodeID string) *Leader {
	return &Leader{pool: pool, key: key, nodeID: nodeID}
}

// TryAcquire attempts to become leader without blocking. Returns true if this
// node is now the leader. Idempotent: calling it again while already leader
// returns true. On success a dedicated connection is checked out and held, and a
// fresh lease row is claimed with a bumped epoch.
//
// Acquisition requires, in order: (1) this node is a PRIMARY (not in recovery);
// (2) the advisory lock is free; (3) the lease row is vacant or stale (or already
// ours). Failing any step leaves this node a follower with no held connection.
func (l *Leader) TryAcquire(ctx context.Context) (bool, error) {
	if l.conn != nil {
		return true, nil // already leader
	}
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	// (1) Never lead from a replica: its advisory locks and lease writes would be
	// meaningless (read-only), and after a promotion the gate clears on its own.
	var inRecovery bool
	if err := conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		conn.Release()
		return false, err
	}
	if inRecovery {
		conn.Release()
		return false, nil
	}
	// (2) Fast in-primary election via the session advisory lock. This is the
	// mutual-exclusion gate: at most one live session per primary holds the key,
	// so the lease claim below only ever runs for the winner.
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&ok); err != nil {
		conn.Release()
		return false, err
	}
	if !ok {
		conn.Release()
		return false, nil
	}
	// (3) Claim the replicated lease unconditionally (we already hold the advisory
	// lock, so no other live session on this primary can be here), bumping epoch so
	// each tenure gets a distinct fencing token. Claiming unconditionally is what
	// keeps same-primary crash failover fast: the new advisory-lock holder need not
	// wait for the dead leader's lease to age past a TTL. The write also fails if
	// this backend is on a demoted (read-only) old primary — a second guard beyond
	// pg_is_in_recovery. The stored epoch fences non-idempotent work (see FenceExec).
	var epoch int64
	err = conn.QueryRow(ctx,
		`INSERT INTO leader_lease (key, holder, epoch, heartbeat_at)
		 VALUES ($1, $2, 1, now())
		 ON CONFLICT (key) DO UPDATE SET
		     holder=$2,
		     epoch=leader_lease.epoch+1,
		     heartbeat_at=now()
		 RETURNING epoch`,
		l.key, l.nodeID).Scan(&epoch)
	if err != nil {
		// Lease claim failed (e.g. read-only backend on a demoted primary). Release
		// the advisory lock so we don't strand it while not-leader.
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key)
		conn.Release()
		return false, err
	}
	l.conn = conn
	var pid int32
	_ = conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
	l.mu.Lock()
	l.epoch = epoch
	l.pid = pid
	l.mu.Unlock()
	return true, nil
}

// BackendPID returns the PostgreSQL backend PID holding the leadership lock, or
// 0 when not leader. Exposed so operators/tests can observe or terminate it.
func (l *Leader) BackendPID() int32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pid
}

// Epoch returns the fencing token of the currently held lease, or 0 when not
// leader. Non-idempotent leader work should pass this to FenceExec so a fenced
// old leader's late write is rejected.
func (l *Leader) Epoch() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.epoch
}

// IsLeader reports whether this node currently holds leadership. It verifies, on
// the dedicated leadership connection itself, that the advisory lock is STILL
// held by this backend — not merely that the connection is reachable. A plain
// Ping only detects this node's own TCP dropping; it cannot detect the case
// where PostgreSQL released the lock (e.g. the backend was terminated
// server-side) while the socket still answers. Querying pg_locks for an advisory
// lock owned by our own backend closes that split-brain window: if the lock is
// gone, we are no longer leader even if the connection is fine. The check is
// non-mutating (unlike a re-entrant pg_try_advisory_lock probe, which could
// spuriously acquire-then-release a freed lock).
func (l *Leader) IsLeader(ctx context.Context) bool {
	if l.conn == nil {
		return false
	}
	// This dedicated connection holds nothing but the leadership advisory lock, so
	// "our backend still holds an advisory lock" is equivalent to "we are leader".
	var held bool
	err := l.conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid())`,
	).Scan(&held)
	if err != nil {
		// Distinguish a DEAD connection from a TRANSIENT error. If the backend died
		// (e.g. pg_terminate_backend, network reset) pgx marks the conn closed and the
		// advisory lock is genuinely gone — step down so a standby can take over and
		// we don't sit in a split-brain window. If the conn is still live, this was a
		// transient error (query timeout, momentary blip): do NOT step down — a healthy
		// leader must not flap on a hiccup. Report last-known state (still leader);
		// FenceExec re-checks lease+epoch on a fresh conn for any non-idempotent work,
		// and the heartbeat/lease bounds a genuinely stuck leader.
		if l.conn.Conn().IsClosed() {
			l.release(ctx)
			return false
		}
		return true
	}
	if !held {
		// DEFINITIVE loss: the query succeeded and our backend no longer holds the
		// lock — we really are not leader. Release and step down.
		l.release(ctx)
		return false
	}
	return true
}

// Heartbeat renews the lease row so standbys keep deferring to us. It returns
// true while we remain leader and false once we have been FENCED — i.e. another
// node has taken the lease (its holder/epoch no longer match ours), which can
// happen after a promotion left us as a stale old primary. A fence (the UPDATE
// matched zero rows) drops leadership (releases the advisory lock + connection)
// so the caller stops its singleton work. A TRANSIENT error, by contrast, does
// NOT step down — see IsLeader. Called each coordinator tick.
func (l *Leader) Heartbeat(ctx context.Context) bool {
	if l.conn == nil {
		return false
	}
	ct, err := l.conn.Exec(ctx,
		`UPDATE leader_lease SET heartbeat_at=now() WHERE key=$1 AND holder=$2 AND epoch=$3`,
		l.key, l.nodeID, l.epoch)
	if err != nil {
		// Dead connection → truly fenced/gone: step down. Transient error on a live
		// connection → a blip; stay leader (see IsLeader) rather than flap.
		if l.conn.Conn().IsClosed() {
			l.release(ctx)
			return false
		}
		return true
	}
	if ct.RowsAffected() == 0 {
		// Definitively fenced: the lease is no longer ours (holder/epoch changed).
		l.release(ctx)
		return false
	}
	return true
}

// FenceExec runs fn inside a transaction and commits it only if, in that same
// transaction, the lease is still ours at the epoch we held. If the lease has
// been taken over (we've been fenced), it rolls back without running fn and
// returns ErrFenced. This is the safe entry point for NON-idempotent leader work
// (e.g. sending a DMARC aggregate report then marking it reported): the fence and
// the write commit atomically, so a partitioned old leader cannot perform the
// side effect after a new leader has taken over.
//
// It borrows a FRESH connection from the pool rather than reusing the leadership
// connection: a leader-work goroutine calls this concurrently with the campaign
// goroutine's Heartbeat/IsLeader on the leadership conn, and a pgx connection is
// not safe for concurrent use. Correctness does not need the advisory-lock
// session — the fence is the committed lease row plus the row lock below.
func (l *Leader) FenceExec(ctx context.Context, fn func(pgx.Tx) error) error {
	l.mu.Lock()
	epoch := l.epoch
	l.mu.Unlock()
	if epoch == 0 {
		return ErrFenced // not leader
	}
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// RepeatableRead gives fn a SINGLE snapshot for the whole transaction. Fenced
	// jobs commonly read-then-write the same rows (e.g. SELECT unreported rows,
	// then UPDATE them reported): under the pgx default READ COMMITTED those two
	// statements take different snapshots, so a row committed by another session in
	// between is invisible to the read but matched by the write — silently marked
	// done without being processed. One snapshot closes that window for every
	// fenced job.
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds
	// FOR UPDATE locks the lease row for the life of the transaction: if another
	// node is concurrently taking over (its INSERT...ON CONFLICT DO UPDATE), this
	// select blocks until that commits and then sees the bumped epoch (no row at
	// our epoch) → fenced. Without the row lock a READ COMMITTED snapshot could
	// pass the check while a takeover commit is in flight, opening a TOCTOU between
	// the check and fn's write.
	var one int
	err = tx.QueryRow(ctx,
		`SELECT 1 FROM leader_lease WHERE key=$1 AND holder=$2 AND epoch=$3 FOR UPDATE`,
		l.key, l.nodeID, epoch).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrFenced
	}
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Resign releases leadership: deletes our lease row (so its absence records a
// clean handover), unlocks the advisory lock, and returns the connection to the
// pool. Safe to call when not leader.
func (l *Leader) Resign(ctx context.Context) error {
	if l.conn == nil {
		return nil
	}
	// Delete only if still ours at our epoch — never clobber a successor's lease.
	_, _ = l.conn.Exec(ctx,
		`DELETE FROM leader_lease WHERE key=$1 AND holder=$2 AND epoch=$3`,
		l.key, l.nodeID, l.epoch)
	// release() performs the explicit advisory unlock (see its doc); it must run
	// even if the delete failed so the lock is never stranded.
	l.release(ctx)
	return nil
}

// release drops the held connection and clears leadership state. It first makes a
// best-effort attempt to free the session advisory lock: returning a connection
// to a pgxpool does NOT reset session state, so without an explicit unlock a
// fenced/lost leader would strand the lock on a live backend and block every
// future campaigner on that key. It is called only from the campaign goroutine
// (the sole mutator of `conn`); it takes `mu` only to publish the pid/epoch
// clear to BackendPID/Epoch/FenceExec readers.
func (l *Leader) release(ctx context.Context) {
	if l.conn != nil {
		_, _ = l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key)
		l.conn.Release()
		l.conn = nil
	}
	l.mu.Lock()
	l.pid = 0
	l.epoch = 0
	l.mu.Unlock()
}
