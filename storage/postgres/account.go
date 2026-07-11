package postgres

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// account implements kernel/store.Account over Postgres. Every mutation runs in
// a transaction that (1) takes a per-account advisory lock, (2) appends Change
// entries to the changelog, (3) folds them into projection tables, (4) advances
// accounts.changelog_seq — atomically. The advisory lock makes seq/uid/modseq
// allocation safe across stateless nodes and auto-releases on COMMIT/ROLLBACK or
// backend crash.
type account struct {
	s        *Store
	id       int64
	tenantID int64
	name     string
}

func (a *account) ID() int64       { return a.id }
func (a *account) TenantID() int64 { return a.tenantID }
func (a *account) Close() error    { return nil }

// pgTx is the store.Tx implementation: a live pgx transaction plus the write
// state (accumulated changelog entries and the running modseq head).
type pgTx struct {
	ctx context.Context
	tx  pgx.Tx
	acc *account

	seq     int64 // running log head; nextModSeq advances it
	changes []store.Change
	entries []pendingEntry
	write   bool // whether this tx may mutate (took the advisory lock)
}

type pendingEntry struct {
	seq       int64
	kind      uint8
	mailboxID int64
	payload   []byte
}

// Tx runs fn in a read-write transaction holding the per-account advisory lock,
// then appends the accumulated changelog and advances the head atomically. The
// resulting []Change is published to subscribers after commit.
func (a *account) Tx(ctx context.Context, fn func(store.Tx) error) error {
	var published []store.Change
	var publishedHead store.ModSeq
	err := pgx.BeginFunc(ctx, a.s.Pool, func(tx pgx.Tx) error {
		// Per-account write serialization uses the ONE-key (64-bit) advisory-lock
		// space, keyed by the full account id (never truncated). PostgreSQL keeps the
		// one-key and two-key spaces disjoint, so this can never collide with the
		// leader-election or schema-bootstrap locks (which use the two-key space with
		// dedicated classids — see ops/ha.lockClassLeader and storage/postgres.Open).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, a.id); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		var head int64
		if err := tx.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, a.id).Scan(&head); err != nil {
			return fmt.Errorf("read changelog head: %w", err)
		}
		pt := &pgTx{ctx: ctx, tx: tx, acc: a, seq: head, write: true}
		if err := fn(pt); err != nil {
			return err
		}
		if err := pt.flush(); err != nil {
			return err
		}
		published = pt.changes
		publishedHead = store.ModSeq(pt.seq)
		return nil
	})
	if err != nil {
		return err
	}
	a.s.publish(ctx, a.id, published, publishedHead)
	return nil
}

// ReadTx runs fn in a READ-ONLY transaction: it takes NO advisory lock (so
// concurrent reads don't serialize against each other or against the writer) and
// never flushes/publishes. fn sees a single MVCC snapshot — the tx runs at
// RepeatableRead so a multi-statement read (e.g. IMAP STATUS, a webapi list's
// count+page, a JMAP query's group scans) is internally consistent even though
// the per-account advisory lock is no longer held to serialize against writers.
// Read-only RepeatableRead is cheap (no serialization failures for read-only
// work). The tx is opened pgx.ReadOnly so any accidental write in fn fails at the
// database, not silently; the write flag is false so flush is a no-op even if
// reached. Use for pure IMAP FETCH/SEARCH/STATUS/SORT and read-only
// JMAP/webapi GETs.
func (a *account) ReadTx(ctx context.Context, fn func(store.Tx) error) error {
	return pgx.BeginTxFunc(ctx, a.s.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		pt := &pgTx{ctx: ctx, tx: tx, acc: a, write: false}
		return fn(pt)
	})
}

// nextModSeq advances and returns the account log offset.
func (pt *pgTx) nextModSeq() store.ModSeq {
	pt.seq++
	return store.ModSeq(pt.seq)
}

// record appends a Change to the pending log and the change list. Every entry
// occupies a unique log position (the changelog PK). For modseq-bearing changes
// the position equals the Change's ModSeq (allocated by the caller via
// nextModSeq). Derived changes (ModSeq -1, e.g. subscription/counts) still
// consume a fresh position so the log is totally ordered, but report no IMAP
// modseq.
func (pt *pgTx) record(c store.Change) error {
	kind, mbID, payload, err := encodeChange(c)
	if err != nil {
		return err
	}
	var seq int64
	if ms := c.ChangeModSeq(); ms >= 0 {
		seq = int64(ms)
	} else {
		pt.seq++ // fresh log position for a derived (non-modseq) entry
		seq = pt.seq
	}
	pt.entries = append(pt.entries, pendingEntry{seq: seq, kind: kind, mailboxID: mbID, payload: payload})
	pt.changes = append(pt.changes, c)
	return nil
}

// flush persists the accumulated changelog entries and the advanced head. On a
// read-only tx (write=false) it is a no-op: nothing was recorded and the head
// must not move.
func (pt *pgTx) flush() error {
	if !pt.write {
		return nil
	}
	for _, e := range pt.entries {
		var mbID any
		if e.mailboxID != 0 {
			mbID = e.mailboxID
		}
		if _, err := pt.tx.Exec(pt.ctx,
			`INSERT INTO changelog (account_id, seq, kind, mailbox_id, payload) VALUES ($1,$2,$3,$4,$5)`,
			pt.acc.id, e.seq, int16(e.kind), mbID, e.payload); err != nil {
			return fmt.Errorf("append changelog: %w", err)
		}
	}
	if _, err := pt.tx.Exec(pt.ctx, `UPDATE accounts SET changelog_seq=$1 WHERE id=$2`, pt.seq, pt.acc.id); err != nil {
		return fmt.Errorf("advance changelog head: %w", err)
	}
	return nil
}

// NextModSeq/NextUIDValidity satisfy the interface (rarely called directly by
// handlers; allocation normally happens inside the mutation helpers).
func (a *account) NextModSeq(tx store.Tx) (store.ModSeq, error) {
	return tx.(*pgTx).nextModSeq(), nil
}

func (a *account) NextUIDValidity(tx store.Tx) (uint32, error) {
	return tx.(*pgTx).nextUIDValidity()
}

// ChangelogHead reads the current account log head without mutating it.
func (a *account) ChangelogHead(ctx context.Context) (store.ModSeq, error) {
	var head int64
	err := a.s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, a.id).Scan(&head)
	return store.ModSeq(head), err
}

// MessageCount reads a mailbox's non-expunged message count via a plain pool
// query (no advisory lock), safe to call from the IDLE loop.
func (a *account) MessageCount(ctx context.Context, mailboxID int64) int {
	var n int
	_ = a.s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE mailbox_id=$1 AND NOT expunged`, mailboxID).Scan(&n)
	return n
}

// URLAuthKey returns the mailbox's URLAUTH access key, creating a random one on
// first use (RFC 4467 §3: the key is auto-generated, RESETKEY not required).
func (a *account) URLAuthKey(ctx context.Context, mailboxID int64) ([]byte, error) {
	var key []byte
	err := a.s.Pool.QueryRow(ctx,
		`SELECT key FROM urlauth_keys WHERE account_id=$1 AND mailbox_id=$2`, a.id, mailboxID).Scan(&key)
	if err == nil {
		return key, nil
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}
	return a.URLAuthResetKey(ctx, mailboxID)
}

// URLAuthResetKey rotates (or creates) the mailbox's URLAUTH key, revoking every
// URL previously authorized against it. Returns the new key.
func (a *account) URLAuthResetKey(ctx context.Context, mailboxID int64) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	_, err := a.s.Pool.Exec(ctx,
		`INSERT INTO urlauth_keys (account_id, mailbox_id, key) VALUES ($1,$2,$3)
		 ON CONFLICT (account_id, mailbox_id) DO UPDATE SET key=EXCLUDED.key`,
		a.id, mailboxID, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// URLAuthResetAll removes all of the account's URLAUTH keys, revoking every
// authorized URL the user has minted (RFC 4467 RESETKEY with no mailbox).
func (a *account) URLAuthResetAll(ctx context.Context) error {
	_, err := a.s.Pool.Exec(ctx, `DELETE FROM urlauth_keys WHERE account_id=$1`, a.id)
	return err
}

// ExpungedUIDsSince returns UIDs removed from a mailbox by change-log entries
// with seq > since, in increasing order. It reads the kindRemoveUIDs entries
// (the durable record of expunges) and unnests their JSON UIDs array — this is
// exactly the data an IMAP QRESYNC VANISHED (EARLIER) response is built from.
func (a *account) ExpungedUIDsSince(ctx context.Context, mailboxID int64, since store.ModSeq) ([]store.UID, error) {
	rows, err := a.s.Pool.Query(ctx,
		`SELECT DISTINCT u::bigint AS uid
		 FROM changelog c, LATERAL jsonb_array_elements_text(c.payload->'UIDs') AS u
		 WHERE c.account_id=$1 AND c.mailbox_id=$2 AND c.kind=$3 AND c.seq > $4
		 ORDER BY uid`,
		a.id, mailboxID, int(kindRemoveUIDs), int64(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uids []store.UID
	for rows.Next() {
		var u int64
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		uids = append(uids, store.UID(u))
	}
	return uids, rows.Err()
}

func (pt *pgTx) nextUIDValidity() (uint32, error) {
	var v int64
	err := pt.tx.QueryRow(pt.ctx,
		`UPDATE accounts SET uidvalidity_next = uidvalidity_next + 1 WHERE id=$1 RETURNING uidvalidity_next - 1`,
		pt.acc.id).Scan(&v)
	return uint32(v), err
}

func (a *account) RegisterComm() *store.Comm { return a.s.registerComm(a.id) }
