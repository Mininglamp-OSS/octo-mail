// Package queue is the shared outbound delivery queue. It follows octo-mail's spine
// pattern: an append-only LOG (queue_log) is the source of truth, and a mutable
// PROJECTION (the queue table) is the folded current state that serves the hot
// due-scan. Every lifecycle fact — enqueued, each attempt, delivered, failed,
// dropped, held — is appended to the log in the SAME transaction that updates the
// projection, so per-attempt history and retired messages are just views over
// the log (no separate results/retired tables to keep in sync).
//
// It is the outbound mirror of the inbound "no node owns an account" property: no
// node owns the queue. Every node runs a Worker that claims due messages with a
// time-bounded lease (SELECT ... FOR UPDATE SKIP LOCKED); if a node crashes
// mid-delivery, its lease expires and another node reclaims the work. The log
// carries the facts; the lease carries the exclusive right to perform the
// external, non-idempotent SMTP side effect — the one thing a log can't provide.
// Delivery is driven by an injected Deliverer so the transport (SMTP client) is
// decoupled from the queue.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Msg is a queued outbound message (metadata; body lives in the blob store).
type Msg struct {
	ID          int64
	TenantID    int64
	AccountID   int64
	MailFrom    string
	RcptTo      string
	BlobRef     string
	Size        int64
	Attempts    int
	MaxAttempts int
	// NotBefore, when non-zero, delays the first delivery attempt until this time
	// (FUTURERELEASE, RFC 4865). Zero means deliver as soon as possible.
	NotBefore time.Time
	// RequireTLS is a per-message TLS-policy override (mirrors mox): nil follows the
	// recipient domain policy (MTA-STS/DANE, else opportunistic); true forces
	// verified STARTTLS and fails rather than downgrade (REQUIRETLS); false allows
	// falling back to plaintext even if a policy would normally require TLS.
	RequireTLS *bool
	// DSN request parameters (RFC 3461), carried from submission so the DSN
	// generator can honor them: Notify is a comma-separated list of
	// NEVER/SUCCESS/FAILURE/DELAY ("" = default = failures+delays); Ret is FULL or
	// HDRS (whether a bounce includes the full original message or headers only);
	// EnvID is echoed as the DSN's Original-Envelope-Id; ORCPT is the original
	// recipient echoed per-recipient.
	Notify string
	Ret    string
	EnvID  string
	ORcpt  string
}

// ResultError is optionally implemented by a Deliverer's returned error to carry
// SMTP result detail (reply code + enhanced status) into the per-attempt results
// history. Errors that don't implement it record code 0 / empty secode.
type ResultError interface {
	error
	SMTPResult() (code int, secode string)
}

// PermanentError is optionally implemented by a Deliverer's returned error to
// signal a permanent (5xx) failure. When an error reports Permanent()==true, the
// worker fails the message immediately — bouncing on the first attempt instead of
// wasting the full retry schedule on a recipient that will never accept it (mirrors
// mox's failMsgsTx permanent path). Errors that don't implement it are treated as
// transient and retried until max attempts.
type PermanentError interface {
	error
	Permanent() bool
}

// backoffFor returns the delay before the next attempt after `attempts` failed
// tries, given a base interval. It mirrors mox: exponential doubling per attempt
// (base, 2×base, 4×base, ...) with ±10% jitter so a fleet of workers retrying a
// down destination don't synchronize into a thundering herd. attempts is the
// number of tries already made (>=1 when rescheduling).
func backoffFor(base time.Duration, attempts int) time.Duration {
	d := base
	// attempts-1 doublings: first retry waits `base`, second `2×base`, etc.
	for i := 1; i < attempts && d < 512*base; i++ {
		d *= 2
	}
	// ±10% jitter.
	jitter := 1.0 + (rand.Float64()*0.2 - 0.1)
	return time.Duration(float64(d) * jitter)
}

// Deliverer performs the actual delivery of one message. Returning nil means
// delivered (message is retired); a non-nil error schedules a retry (or retires
// as failed once max attempts is reached). Must be idempotent w.r.t. (ID,
// Attempts) — a lease can expire after delivery but before retire, causing a
// re-claim; the Deliverer should tolerate a duplicate send or dedup upstream.
type Deliverer func(ctx context.Context, m Msg) error

// Log entry kinds (queue_log.kind). The log is the source of truth; the queue
// table is its fold. Terminal kinds (delivered/failed/dropped) carry keep_until.
const (
	kindEnqueued    = "enqueued"
	kindAttempt     = "attempt"   // one delivery attempt outcome
	kindDelivered   = "delivered" // terminal: success
	kindFailed      = "failed"    // terminal: permanent failure / max attempts
	kindDropped     = "dropped"   // terminal: admin cancel (no DSN)
	kindRescheduled = "rescheduled"
	kindDelayed     = "delayed" // delayed-delivery warning DSN emitted
	kindHeld        = "held"
	kindUnheld      = "unheld"
	kindScheduled   = "scheduled" // next_attempt changed by admin
	kindRequireTLS  = "requiretls"
)

// execer is anything that can run a statement: a *pgxpool.Pool (its own
// transaction) or a pgx.Tx (the caller's). Lets appendLog serve both a
// standalone append and one enrolled in a larger transaction.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// appendLog appends one fact about a queue message to the source-of-truth log.
// keep is non-nil only for terminal entries and sets the retention horizon for
// the whole message's log.
func appendLog(ctx context.Context, db execer, m Msg, kind string, payload any, keep *time.Time) error {
	raw := []byte("{}")
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	_, err := db.Exec(ctx,
		`INSERT INTO queue_log (queue_id, tenant_id, account_id, rcpt_to, kind, payload, keep_until)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		m.ID, m.TenantID, m.AccountID, m.RcptTo, kind, raw, keep)
	return err
}

// Enqueue adds a message to the shared queue. If any hold rule for the message's
// tenant matches, the message is enqueued already on hold (auto-hold) so it is
// not delivered until an operator resumes it.
func Enqueue(ctx context.Context, pool *pgxpool.Pool, m Msg) (int64, error) {
	var id int64
	// next_attempt defaults to now(); a non-zero NotBefore defers the first
	// attempt (FUTURERELEASE) via COALESCE.
	var notBefore any
	if !m.NotBefore.IsZero() {
		notBefore = m.NotBefore
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		hold, herr := matchesHoldRule(ctx, tx, m)
		if herr != nil {
			return herr
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO queue (tenant_id, account_id, mail_from, rcpt_to, blob_ref, size, next_attempt, hold, require_tls, dsn_notify, dsn_ret, dsn_envid, dsn_orcpt)
			 VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7,now()),$8,$9,$10,$11,$12,$13) RETURNING id`,
			m.TenantID, m.AccountID, m.MailFrom, m.RcptTo, m.BlobRef, m.Size, notBefore, hold, m.RequireTLS,
			m.Notify, m.Ret, m.EnvID, m.ORcpt).Scan(&id); err != nil {
			return err
		}
		// Append the enqueued fact to the source-of-truth log (same tx as the
		// projection insert). m.ID is now known.
		m.ID = id
		return appendLog(ctx, tx, m, kindEnqueued, map[string]any{"hold": hold, "size": m.Size}, nil)
	})
	return id, err
}

// Worker claims and delivers due messages on one node.
type Worker struct {
	Pool    *pgxpool.Pool
	NodeID  string // unique per node/process
	Deliver Deliverer
	Lease   time.Duration // how long a claim is held (default 30s)
	Batch   int           // max messages per claim (default 10)
	Backoff time.Duration // base retry delay; doubles per attempt (default 5s)

	// RetiredKeep is how long a retired message (and its results) is kept before
	// the cleanup sweep removes it. Zero uses the schema default (7 days).
	RetiredKeep time.Duration

	// DelayThreshold is the attempt count at which a "still trying" delayed-delivery
	// warning DSN is sent (once). Zero disables delayed DSNs.
	DelayThreshold int

	// OnFailed, if set, is called once when a message is permanently failed
	// (max attempts reached) and successfully retired by THIS worker. Used to
	// generate a DSN (bounce) back to the sender. Best-effort: an error is
	// returned up from RunOnce but the message is already retired.
	OnFailed func(ctx context.Context, m Msg) error

	// OnDelayed, if set, is called once per message when its attempt count first
	// reaches DelayThreshold (and it is still being retried). Used to send a
	// delayed-delivery warning DSN. Best-effort.
	OnDelayed func(ctx context.Context, m Msg) error

	// ObserveDelivery, if set, is called after each delivery attempt with its
	// duration and result ("ok" or "error"). Used to feed a metrics histogram
	// without coupling the queue package to the observability layer.
	ObserveDelivery func(d time.Duration, result string)
}

func (w *Worker) lease() time.Duration {
	if w.Lease == 0 {
		return 30 * time.Second
	}
	return w.Lease
}

// deliveryTimeout bounds a single delivery so it cannot run past the lease
// window (after which another node may reclaim and re-send the message). It is
// the lease minus a safety margin for DB/node clock skew and the retire round
// trip — a delivery that would exceed this is aborted and rescheduled rather
// than risk a double-send.
func (w *Worker) deliveryTimeout() time.Duration {
	lease := w.lease()
	margin := lease / 5 // 20% headroom
	if margin < time.Second {
		margin = time.Second
	}
	if margin >= lease {
		return lease
	}
	return lease - margin
}

// renewLease resets this message's lease to a fresh full window, but only if
// this node still holds it (leased_by = NodeID and not yet expired). It returns
// held=false when the lease was lost to another node, signaling the caller to
// skip delivery. This makes each message in a batch deliver on its own full
// window instead of the shared, eroding window from the initial claim.
func (w *Worker) renewLease(ctx context.Context, m Msg) (held bool, err error) {
	tag, err := w.Pool.Exec(ctx,
		`UPDATE queue SET lease_until=now()+$3::interval
		 WHERE id=$1 AND leased_by=$2 AND lease_until > now()`,
		m.ID, w.NodeID, w.lease().String())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
func (w *Worker) batch() int {
	if w.Batch == 0 {
		return 10
	}
	return w.Batch
}
func (w *Worker) backoff() time.Duration {
	if w.Backoff == 0 {
		return 5 * time.Second
	}
	return w.Backoff
}

// RunOnce claims up to Batch due messages, delivers each, and retires or
// reschedules them. Returns the number of messages processed. Nodes call this on
// a tick; concurrent nodes never claim the same row (FOR UPDATE SKIP LOCKED).
//
// Fencing: retire/reschedule only act on rows THIS node still leases
// (leased_by = NodeID). If our lease already expired and another node reclaimed
// the message (we were a slow/stale worker), our writes are no-ops — the current
// leaseholder owns the outcome. This prevents a stale node from resurrecting or
// double-retiring reclaimed work.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	msgs, err := w.claim(ctx)
	if err != nil {
		return 0, err
	}
	// Process each claimed message independently: a per-message retire/reschedule
	// error must not abandon the rest of the batch (they are already leased with
	// attempts incremented, and would otherwise sit stranded until lease expiry).
	var firstErr error
	for _, m := range msgs {
		// Renew this message's lease to a fresh full window immediately before
		// delivering it. The batch was leased together in claim(), so without
		// renewal the Nth message would deliver on a lease already eroded by the
		// N-1 deliveries ahead of it. If renewal shows we no longer hold the lease
		// (a slow tick let it expire and another node reclaimed the row), skip
		// delivery — that node now owns the outcome, and delivering here would be
		// the double-send we are preventing.
		held, rerr := w.renewLease(ctx, m)
		if rerr != nil {
			if firstErr == nil {
				firstErr = rerr
			}
			continue
		}
		if !held {
			continue
		}

		// Bound the delivery to strictly less than the lease window so this node
		// stops transmitting before lease_until can pass and another node reclaim
		// the row. The margin absorbs clock skew between the DB (which stamps
		// lease_until via now()) and this node (which enforces the timeout).
		dctx, cancel := context.WithTimeout(ctx, w.deliveryTimeout())
		start := time.Now()
		derr := w.Deliver(dctx, m)
		dur := time.Since(start)
		cancel()
		// A real delivery attempt was made: count it now (not at claim time), so
		// a lost lease / crash before delivery never burns the retry budget. This
		// is the authoritative attempt number for the result log and the
		// failure/backoff decision below.
		m.Attempts++
		if w.ObserveDelivery != nil {
			result := "ok"
			if derr != nil {
				result = "error"
			}
			w.ObserveDelivery(dur, result)
		}
		// Record this attempt's outcome (best-effort; a result-log error must not
		// abandon the retire/reschedule of the message itself).
		if rerr := w.recordResult(ctx, m, start, dur, derr); rerr != nil && firstErr == nil {
			firstErr = rerr
		}
		var perr error
		if derr == nil {
			_, perr = w.retire(ctx, m, true)
		} else {
			perr = w.reschedule(ctx, m, derr)
		}
		if perr != nil && firstErr == nil {
			firstErr = perr
		}
	}
	return len(msgs), firstErr
}

// recordResult appends an attempt entry to the log (mirrors mox markResult). code
// and secode are extracted from the delivery error when it implements
// ResultError; otherwise 0 / "". A nil derr records a success.
func (w *Worker) recordResult(ctx context.Context, m Msg, start time.Time, dur time.Duration, derr error) error {
	success := derr == nil
	code, secode, errStr := 0, "", ""
	if derr != nil {
		errStr = derr.Error()
		var re ResultError
		if errors.As(derr, &re) {
			code, secode = re.SMTPResult()
		}
	}
	return appendLog(ctx, w.Pool, m, kindAttempt, map[string]any{
		"n": m.Attempts, "start": start, "duration_ms": dur.Milliseconds(),
		"success": success, "code": code, "secode": secode, "error": errStr,
	}, nil)
}

// claim atomically leases up to Batch due messages to this node. A message is
// "due" when next_attempt has passed AND it is not on hold AND it is either
// unleased or its lease has expired (the owning node is presumed dead).
func (w *Worker) claim(ctx context.Context) ([]Msg, error) {
	rows, err := w.Pool.Query(ctx,
		`UPDATE queue SET leased_by=$1, lease_until=now()+$2::interval, last_attempt=now()
		 WHERE id IN (
		     SELECT id FROM queue
		     WHERE next_attempt <= now()
		       AND hold = false
		       AND (lease_until IS NULL OR lease_until < now())
		     ORDER BY next_attempt
		     FOR UPDATE SKIP LOCKED
		     LIMIT $3
		 )
		 RETURNING id, tenant_id, account_id, mail_from, rcpt_to, blob_ref, size, attempts, max_attempts, require_tls,
		           COALESCE(dsn_notify,''), COALESCE(dsn_ret,''), COALESCE(dsn_envid,''), COALESCE(dsn_orcpt,'')`,
		w.NodeID, w.lease().String(), w.batch())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Msg
	for rows.Next() {
		var m Msg
		if err := rows.Scan(&m.ID, &m.TenantID, &m.AccountID, &m.MailFrom, &m.RcptTo, &m.BlobRef, &m.Size, &m.Attempts, &m.MaxAttempts, &m.RequireTLS,
			&m.Notify, &m.Ret, &m.EnvID, &m.ORcpt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// retire removes a message from the projection and appends a terminal log entry
// (delivered on success, failed otherwise) carrying the retention horizon. Fenced
// by leased_by: a stale node whose lease was reclaimed retires nothing. Returns
// whether this call actually retired the row (true) or it was already gone.
func (w *Worker) retire(ctx context.Context, m Msg, success bool) (bool, error) {
	acted := false
	keep := time.Now().Add(w.retiredKeep())
	err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM queue WHERE id=$1 AND leased_by=$2`, m.ID, w.NodeID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil // no longer ours; current leaseholder owns the outcome
		}
		acted = true
		kind := kindDelivered
		if !success {
			kind = kindFailed
		}
		return appendLog(ctx, tx, m, kind, map[string]any{"attempts": m.Attempts}, &keep)
	})
	return acted, err
}

// defaultRetiredKeep is how long a message's terminal log entry (and thus its
// whole log) is retained before the cleanup sweep removes it, when no explicit
// Worker.RetiredKeep is configured. Admin Fail/Drop use it directly.
const defaultRetiredKeep = 7 * 24 * time.Hour

func (w *Worker) retiredKeep() time.Duration {
	if w.RetiredKeep > 0 {
		return w.RetiredKeep
	}
	return defaultRetiredKeep
}

// reschedule releases the lease and backs off exponentially, or retires as
// failed at max attempts. Fenced by leased_by so a stale worker can't reset a
// reclaimed row. On permanent failure that this worker actually retired, fires
// OnFailed (bounce DSN); when the attempt count first reaches DelayThreshold it
// fires OnDelayed once (a "still trying" warning DSN). lastErr is recorded on the
// projection and in the rescheduled log entry.
//
// The failure decision uses m.MaxAttempts carried from claim (no extra SELECT).
// The retry path is a single transaction: one atomic projection UPDATE that also
// sets delayed_dsn (deduping the warning), plus the rescheduled/delayed log
// appends — the log and its fold move together.
func (w *Worker) reschedule(ctx context.Context, m Msg, lastErr error) error {
	// Permanent (5xx) failure, or the retry budget is exhausted: fail now — retire
	// as failed and fire OnFailed (bounce DSN + suppression). A permanent error
	// short-circuits the remaining retry schedule (mox failMsgsTx permanent path).
	var perm PermanentError
	permanent := errors.As(lastErr, &perm) && perm.Permanent()
	if permanent || m.Attempts >= m.MaxAttempts {
		acted, rerr := w.retire(ctx, m, false)
		if rerr != nil {
			return rerr
		}
		if acted && w.OnFailed != nil {
			return w.OnFailed(ctx, m)
		}
		return nil
	}
	errStr := ""
	if lastErr != nil {
		errStr = lastErr.Error()
	}
	backoff := backoffFor(w.backoff(), m.Attempts)
	wantDelay := w.OnDelayed != nil && w.DelayThreshold > 0 && m.Attempts >= w.DelayThreshold

	// Single transaction: release the lease + back off + record the error, and
	// (idempotently) flip delayed_dsn. A CTE captures the pre-update delayed_dsn
	// (fenced by leased_by) so we can detect the false→true transition and fire
	// the OnDelayed hook exactly once, even across lease re-claims.
	var acted, firedDelay bool
	err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		var wasDelayed bool
		err := tx.QueryRow(ctx,
			`WITH prev AS (
			     SELECT id, delayed_dsn AS old FROM queue
			     WHERE id=$1 AND leased_by=$2 FOR UPDATE
			 )
			 UPDATE queue q SET leased_by=NULL, lease_until=NULL, next_attempt=now()+$3::interval,
			     last_error=$4, attempts=$6, delayed_dsn=q.delayed_dsn OR $5
			 FROM prev WHERE q.id=prev.id
			 RETURNING prev.old`,
			m.ID, w.NodeID, backoff.String(), errStr, wantDelay, m.Attempts).Scan(&wasDelayed)
		if err == pgx.ErrNoRows {
			return nil // reclaimed/retired by another node; not ours anymore
		}
		if err != nil {
			return err
		}
		acted = true
		// The delayed warning transitions on THIS call iff we asked for it and it
		// was not already set — dedup across lease re-claims.
		firedDelay = wantDelay && !wasDelayed
		if err := appendLog(ctx, tx, m, kindRescheduled, map[string]any{
			"attempt": m.Attempts, "next_in_ms": backoff.Milliseconds(), "error": errStr,
		}, nil); err != nil {
			return err
		}
		if firedDelay {
			return appendLog(ctx, tx, m, kindDelayed, map[string]any{"attempt": m.Attempts}, nil)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if acted && firedDelay {
		return w.OnDelayed(ctx, m)
	}
	return nil
}
