package queue

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/core/addr"
)

// Filter selects which queued messages an admin operation applies to. A zero
// Filter matches every message; set fields narrow it (AND-combined). This is the
// octo-mail equivalent of mox's queue admin filters.
type Filter struct {
	IDs       []int64 // specific message ids
	TenantID  int64   // 0 = any tenant
	AccountID int64   // 0 = any account
	Recipient string  // exact rcpt_to match; "" = any
}

// where builds the WHERE clause (without the leading "WHERE") and args for this
// filter, starting placeholders at $start. Returns "true" when the filter is
// empty so it can always be embedded after WHERE.
func (f Filter) where(start int) (string, []any) {
	return f.whereCol("id", start)
}

// whereCol is like where but names the id column, so the same filter can select
// against queue.id or the log's queue_id.
func (f Filter) whereCol(idCol string, start int) (string, []any) {
	var conds []string
	var args []any
	n := start
	if len(f.IDs) > 0 {
		conds = append(conds, fmt.Sprintf("%s = ANY($%d)", idCol, n))
		args = append(args, f.IDs)
		n++
	}
	if f.TenantID != 0 {
		conds = append(conds, fmt.Sprintf("tenant_id = $%d", n))
		args = append(args, f.TenantID)
		n++
	}
	if f.AccountID != 0 {
		conds = append(conds, fmt.Sprintf("account_id = $%d", n))
		args = append(args, f.AccountID)
		n++
	}
	if f.Recipient != "" {
		conds = append(conds, fmt.Sprintf("rcpt_to = $%d", n))
		args = append(args, f.Recipient)
		n++
	}
	if len(conds) == 0 {
		return "true", nil
	}
	return strings.Join(conds, " AND "), args
}

// Entry is a queue row as seen by admin listing (includes scheduling state that
// the delivery path doesn't need).
type Entry struct {
	ID          int64
	TenantID    int64
	AccountID   int64
	MailFrom    string
	RcptTo      string
	Size        int64
	Attempts    int
	MaxAttempts int
	NextAttempt time.Time
	Hold        bool
	LastAttempt *time.Time
	LastError   string
	RequireTLS  *bool
	LeasedBy    string
	CreatedAt   time.Time
}

// List returns queued messages matching the filter, most-recently-created first.
func List(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]Entry, error) {
	cond, args := f.where(1)
	rows, err := pool.Query(ctx,
		`SELECT id, tenant_id, account_id, mail_from, rcpt_to, size, attempts, max_attempts,
		        next_attempt, hold, last_attempt, COALESCE(last_error,''), require_tls, COALESCE(leased_by,''), created_at
		 FROM queue WHERE `+cond+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AccountID, &e.MailFrom, &e.RcptTo, &e.Size,
			&e.Attempts, &e.MaxAttempts, &e.NextAttempt, &e.Hold, &e.LastAttempt, &e.LastError,
			&e.RequireTLS, &e.LeasedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// mutateLog runs a statement that must RETURN id, tenant_id, account_id, rcpt_to
// for every affected row (an UPDATE ... RETURNING or DELETE ... RETURNING), then
// appends one log entry of the given kind per affected row — all in one
// transaction, preserving the spine invariant that a projection change and its
// logged fact commit together. keep is non-nil for terminal kinds (sets the
// retention horizon). Returns the affected count.
func mutateLog(ctx context.Context, pool *pgxpool.Pool, kind string, payload any, keep *time.Time, sql string, args ...any) (int64, error) {
	var affected []Msg
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var m Msg
			if err := rows.Scan(&m.ID, &m.TenantID, &m.AccountID, &m.RcptTo); err != nil {
				rows.Close()
				return err
			}
			affected = append(affected, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, m := range affected {
			if err := appendLog(ctx, tx, m, kind, payload, keep); err != nil {
				return err
			}
		}
		return nil
	})
	return int64(len(affected)), err
}

const returningIdent = ` RETURNING id, tenant_id, account_id, rcpt_to`

// Kick makes matching messages due immediately (next_attempt=now) and clears any
// hold, so the next worker tick attempts them. Returns the number affected. This
// is the "schedule now" / retry-now admin action. Leased rows are left alone
// (their current attempt is in flight); only unleased rows are rescheduled.
func Kick(ctx context.Context, pool *pgxpool.Pool, f Filter) (int64, error) {
	cond, args := f.where(1)
	return mutateLog(ctx, pool, kindScheduled, map[string]any{"op": "kick"}, nil,
		`UPDATE queue SET next_attempt=now(), hold=false WHERE leased_by IS NULL AND (`+cond+`)`+returningIdent, args...)
}

// Schedule adds d to the next_attempt of matching (unleased) messages. A negative
// d moves delivery earlier. Returns the number affected.
func Schedule(ctx context.Context, pool *pgxpool.Pool, f Filter, d time.Duration) (int64, error) {
	cond, args := f.where(2)
	// Pass seconds through make_interval rather than d.String(): Go's duration
	// format ("7m30s", "980µs") is not valid Postgres interval syntax and "m"
	// would be read as months.
	args = append([]any{d.Seconds()}, args...)
	return mutateLog(ctx, pool, kindScheduled, map[string]any{"op": "schedule", "delta": d.String()}, nil,
		`UPDATE queue SET next_attempt=next_attempt+make_interval(secs => $1) WHERE leased_by IS NULL AND (`+cond+`)`+returningIdent, args...)
}

// ScheduleAt sets next_attempt to an absolute time for matching (unleased)
// messages (mox NextAttemptSet). Returns the number affected.
func ScheduleAt(ctx context.Context, pool *pgxpool.Pool, f Filter, t time.Time) (int64, error) {
	cond, args := f.where(2)
	args = append([]any{t}, args...)
	return mutateLog(ctx, pool, kindScheduled, map[string]any{"op": "schedule-at", "at": t}, nil,
		`UPDATE queue SET next_attempt=$1 WHERE leased_by IS NULL AND (`+cond+`)`+returningIdent, args...)
}

// RequireTLSSet sets the per-message TLS override on matching messages (mox
// RequireTLSSet): nil follows policy, true forces verified STARTTLS, false allows
// plaintext fallback. Returns the number affected.
func RequireTLSSet(ctx context.Context, pool *pgxpool.Pool, f Filter, requireTLS *bool) (int64, error) {
	cond, args := f.where(2)
	args = append([]any{requireTLS}, args...)
	return mutateLog(ctx, pool, kindRequireTLS, map[string]any{"require_tls": requireTLS}, nil,
		`UPDATE queue SET require_tls=$1 WHERE `+cond+returningIdent, args...)
}

// HoldSet pauses (hold=true) or resumes (hold=false) matching messages. A held
// message is never claimed for delivery until resumed. Returns the number affected.
func HoldSet(ctx context.Context, pool *pgxpool.Pool, f Filter, hold bool) (int64, error) {
	cond, args := f.where(2)
	args = append([]any{hold}, args...)
	kind := kindUnheld
	if hold {
		kind = kindHeld
	}
	return mutateLog(ctx, pool, kind, nil, nil,
		`UPDATE queue SET hold=$1 WHERE `+cond+returningIdent, args...)
}

// Drop removes matching messages from the queue WITHOUT sending a DSN (silent
// cancel), appending a terminal "dropped" log entry (with retention horizon) per
// message. Leased rows are dropped too (admin intent overrides an in-flight
// attempt; the delivering worker's later retire is a fenced no-op once the row is
// gone). Returns the number removed.
func Drop(ctx context.Context, pool *pgxpool.Pool, f Filter) (int64, error) {
	cond, args := f.where(1)
	keep := time.Now().Add(defaultRetiredKeep)
	return mutateLog(ctx, pool, kindDropped, nil, &keep,
		`DELETE FROM queue WHERE `+cond+returningIdent, args...)
}

// Fail removes matching messages and sends a permanent-failure DSN for each via
// onFailed (typically the same DSN generator the worker uses at max attempts).
// Returns the number failed. onFailed is best-effort per message; the first hook
// error is returned after all rows are processed. Each removed message gets a
// terminal "failed" log entry (with retention horizon) in the same transaction
// as its projection delete, so the fenced delete and the logged fact commit
// together — only then is the DSN fired.
func Fail(ctx context.Context, pool *pgxpool.Pool, f Filter, onFailed func(context.Context, Msg) error) (int64, error) {
	cond, args := f.where(1)
	rows, err := pool.Query(ctx,
		`SELECT id, tenant_id, account_id, mail_from, rcpt_to, blob_ref, size, attempts,
		        COALESCE(dsn_notify,''), COALESCE(dsn_ret,''), COALESCE(dsn_envid,''), COALESCE(dsn_orcpt,'')
		 FROM queue WHERE `+cond, args...)
	if err != nil {
		return 0, err
	}
	var msgs []Msg
	for rows.Next() {
		var m Msg
		if err := rows.Scan(&m.ID, &m.TenantID, &m.AccountID, &m.MailFrom, &m.RcptTo, &m.BlobRef, &m.Size, &m.Attempts,
			&m.Notify, &m.Ret, &m.EnvID, &m.ORcpt); err != nil {
			rows.Close()
			return 0, err
		}
		msgs = append(msgs, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	keep := time.Now().Add(defaultRetiredKeep)
	var count int64
	var firstErr error
	for _, m := range msgs {
		// Delete the projection row and append the terminal fact atomically; only
		// fire the DSN if this call actually removed the row, so concurrent
		// admins/workers can't double-bounce.
		acted := false
		terr := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			ct, derr := tx.Exec(ctx, `DELETE FROM queue WHERE id=$1`, m.ID)
			if derr != nil {
				return derr
			}
			if ct.RowsAffected() == 0 {
				return nil
			}
			acted = true
			return appendLog(ctx, tx, m, kindFailed, map[string]any{"attempts": m.Attempts, "admin": true}, &keep)
		})
		if terr != nil {
			if firstErr == nil {
				firstErr = terr
			}
			continue
		}
		if !acted {
			continue
		}
		count++
		if onFailed != nil {
			if herr := onFailed(ctx, m); herr != nil && firstErr == nil {
				firstErr = herr
			}
		}
	}
	return count, firstErr
}

// ---------------------------------------------------------------------------
// Results history + retired listing / retention cleanup.
// ---------------------------------------------------------------------------

// Result is one recorded delivery attempt (mirrors mox MsgResult), read from the
// log's attempt entries.
type Result struct {
	Attempt  int
	Start    time.Time
	Duration time.Duration
	Success  bool
	Code     int
	Secode   string
	Error    string
}

// Results returns the per-attempt delivery history for a queue message id (live
// or retired — the id is stable across the message's life), oldest attempt first.
// It reads the attempt entries from the source-of-truth log.
func Results(ctx context.Context, pool *pgxpool.Pool, queueID int64) ([]Result, error) {
	rows, err := pool.Query(ctx,
		`SELECT payload FROM queue_log WHERE queue_id=$1 AND kind=$2 ORDER BY id`, queueID, kindAttempt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var p struct {
			N          int       `json:"n"`
			Start      time.Time `json:"start"`
			DurationMS int64     `json:"duration_ms"`
			Success    bool      `json:"success"`
			Code       int       `json:"code"`
			Secode     string    `json:"secode"`
			Error      string    `json:"error"`
		}
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, Result{
			Attempt: p.N, Start: p.Start, Duration: time.Duration(p.DurationMS) * time.Millisecond,
			Success: p.Success, Code: p.Code, Secode: p.Secode, Error: p.Error,
		})
	}
	return out, rows.Err()
}

// RetiredEntry is a retired (delivered/failed/dropped) message, read from the
// log's terminal entries.
type RetiredEntry struct {
	ID        int64
	TenantID  int64
	AccountID int64
	RcptTo    string
	Success   bool
	Kind      string // delivered | failed | dropped
	Attempts  int
	RetiredAt time.Time
	KeepUntil time.Time
}

// RetiredList returns retired messages matching the filter, most-recent first. A
// message is "retired" once it has a terminal log entry (delivered/failed/
// dropped); those entries are the history.
func RetiredList(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]RetiredEntry, error) {
	// The filter's id column is queue_log.queue_id here; tenant/account/rcpt match
	// the denormalized columns on the log. Terminal entries are selected by kind
	// (bound as parameters) — keep_until is a retention detail, not the identity of
	// a terminal fact.
	cond, args := f.whereCol("queue_id", 2)
	args = append([]any{[]string{kindDelivered, kindFailed, kindDropped}}, args...)
	rows, err := pool.Query(ctx,
		`SELECT queue_id, tenant_id, account_id, rcpt_to, kind,
		        COALESCE((payload->>'attempts')::int, 0), created_at, keep_until
		 FROM queue_log
		 WHERE kind = ANY($1) AND (`+cond+`)
		 ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetiredEntry
	for rows.Next() {
		var e RetiredEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AccountID, &e.RcptTo, &e.Kind, &e.Attempts, &e.RetiredAt, &e.KeepUntil); err != nil {
			return nil, err
		}
		e.Success = e.Kind == kindDelivered
		out = append(out, e)
	}
	return out, rows.Err()
}

// CleanupRetired deletes the entire log of any message whose terminal entry's
// keep_until has passed — retention operates on the log itself (the source of
// truth), removing attempt history and terminal entries together. Live messages
// (no terminal entry) are untouched. Returns the number of messages swept.
func CleanupRetired(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var swept int64
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// Snapshot the expired message ids, then delete their whole log. Counting the
		// ids (not raw log rows) reports messages swept.
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT queue_id FROM queue_log WHERE keep_until IS NOT NULL AND keep_until < now()`)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM queue_log WHERE queue_id = ANY($1)`, ids); err != nil {
			return err
		}
		swept = int64(len(ids))
		return nil
	})
	return swept, err
}

// DepthCounts is a snapshot of outbound queue depth for metrics/observability.
type DepthCounts struct {
	Total int64 // all live queue rows
	Due   int64 // deliverable now: not held, not leased, next_attempt reached
	Held  int64 // paused via hold=true
}

// Depth returns the current queue depth counts in a single scan.
func Depth(ctx context.Context, pool *pgxpool.Pool) (DepthCounts, error) {
	var d DepthCounts
	err := pool.QueryRow(ctx,
		`SELECT count(*),
		        count(*) FILTER (WHERE hold=false AND leased_by IS NULL AND next_attempt <= now()),
		        count(*) FILTER (WHERE hold=true)
		 FROM queue`).Scan(&d.Total, &d.Due, &d.Held)
	return d, err
}

// ---------------------------------------------------------------------------
// Hold rules — auto-hold newly-enqueued (and existing) messages by criteria.
// ---------------------------------------------------------------------------

// HoldRule auto-holds outbound messages matching its (AND-combined) criteria. A
// zero-valued optional field is a wildcard. AccountID 0 means "any account in the
// tenant". SenderDomain/RecipientDomain "" mean "any". Mirrors mox's HoldRule:
// freeze a class of mail (a compromised account, a domain under investigation)
// without dropping it.
type HoldRule struct {
	ID              int64
	TenantID        int64
	AccountID       int64
	SenderDomain    string
	RecipientDomain string
}

// HoldRuleAdd inserts a rule and immediately holds all existing queued messages
// that match it. Returns the new rule id and the count of messages held.
func HoldRuleAdd(ctx context.Context, pool *pgxpool.Pool, hr HoldRule) (int64, int64, error) {
	var id int64
	var held int64
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO queue_hold_rules (tenant_id, account_id, sender_domain, recipient_domain)
			 VALUES ($1, NULLIF($2,0::bigint), NULLIF($3,''), NULLIF($4,'')) RETURNING id`,
			hr.TenantID, hr.AccountID, hr.SenderDomain, hr.RecipientDomain).Scan(&id); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx,
			`UPDATE queue SET hold=true
			 WHERE hold=false AND tenant_id=$1
			   AND ($2=0::bigint OR account_id=$2)
			   AND ($3='' OR split_part(mail_from,'@',2)=$3)
			   AND ($4='' OR split_part(rcpt_to,'@',2)=$4)`,
			hr.TenantID, hr.AccountID, hr.SenderDomain, hr.RecipientDomain)
		if err != nil {
			return err
		}
		held = ct.RowsAffected()
		return nil
	})
	return id, held, err
}

// HoldRuleRemove deletes a rule. Existing hold states are left unchanged (an
// operator resumes messages explicitly via HoldSet), matching mox semantics.
func HoldRuleRemove(ctx context.Context, pool *pgxpool.Pool, id int64) error {
	_, err := pool.Exec(ctx, `DELETE FROM queue_hold_rules WHERE id=$1`, id)
	return err
}

// HoldRuleList returns all hold rules for a tenant (or all tenants when 0).
func HoldRuleList(ctx context.Context, pool *pgxpool.Pool, tenantID int64) ([]HoldRule, error) {
	var rows pgx.Rows
	var err error
	if tenantID == 0 {
		rows, err = pool.Query(ctx,
			`SELECT id, tenant_id, COALESCE(account_id,0), COALESCE(sender_domain,''), COALESCE(recipient_domain,'')
			 FROM queue_hold_rules ORDER BY id`)
	} else {
		rows, err = pool.Query(ctx,
			`SELECT id, tenant_id, COALESCE(account_id,0), COALESCE(sender_domain,''), COALESCE(recipient_domain,'')
			 FROM queue_hold_rules WHERE tenant_id=$1 ORDER BY id`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HoldRule
	for rows.Next() {
		var hr HoldRule
		if err := rows.Scan(&hr.ID, &hr.TenantID, &hr.AccountID, &hr.SenderDomain, &hr.RecipientDomain); err != nil {
			return nil, err
		}
		out = append(out, hr)
	}
	return out, rows.Err()
}

// matchesHoldRule reports, within tx, whether any hold rule for the tenant matches
// the given message. Used by Enqueue to auto-hold on insert.
func matchesHoldRule(ctx context.Context, tx pgx.Tx, m Msg) (bool, error) {
	senderDom := addr.Domain(m.MailFrom)
	rcptDom := addr.Domain(m.RcptTo)
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		     SELECT 1 FROM queue_hold_rules
		     WHERE tenant_id=$1
		       AND (account_id IS NULL OR account_id=$2)
		       AND (sender_domain IS NULL OR sender_domain=$3)
		       AND (recipient_domain IS NULL OR recipient_domain=$4)
		 )`,
		m.TenantID, m.AccountID, senderDom, rcptDom).Scan(&exists)
	return exists, err
}
