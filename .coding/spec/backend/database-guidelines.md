# Database Guidelines

octo-mail persists everything in **PostgreSQL 17** (the change-log spine +
projections) and message bodies in **S3/FS blobs**. The DB layer lives entirely in
`storage/postgres/`; nothing above the interface line touches it.

---

## Driver: pgx v5, raw SQL, no ORM

Use `github.com/jackc/pgx/v5` directly with hand-written SQL and `$1` placeholders.
There is no ORM and no query builder for storage — the only "query builder" is the
bounded `store.MessageQuery` interface (`core/store/account.go`) that hides SQL from
consumers.

- Reads: `tx.QueryRow(ctx, sql, args...).Scan(...)` / `tx.Query(...)`.
- Writes: `tx.Exec(ctx, sql, args...)`.
- Pool-level reads outside a tx: `a.s.Pool.QueryRow(ctx, ...)`.

Reference: `storage/postgres/message.go`, `storage/postgres/mailbox.go`.

---

## The per-account advisory lock (★ read this before any write path)

Every **read-write** transaction for an account must take the per-account advisory
lock as its **first statement**, then read the changelog head, then run work, then
flush the accumulated changelog. This is what serializes `seq`/`uid`/`modseq`
allocation across stateless nodes. The canonical implementation is
`account.Tx` in `storage/postgres/account.go`:

```go
if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, a.id); err != nil {
    return fmt.Errorf("advisory lock: %w", err)
}
// read changelog_seq head, run fn(pt), then pt.flush()
```

Key rules:

- Use the **one-key** advisory space keyed by the full `account_id` (never
  truncated). The two-key space is reserved for leader election
  (`ops/ha`) and schema bootstrap (`storage/postgres/store.go`) — do not collide.
- `pg_advisory_xact_lock` auto-releases on COMMIT/ROLLBACK/backend crash — exactly
  what HA needs. Never take a session-level advisory lock on the write path.
- **Read-only** work uses `account.ReadTx`: no advisory lock, opened
  `pgx.ReadOnly` + `pgx.RepeatableRead` for an internally-consistent multi-statement
  snapshot. Use it for IMAP FETCH/SEARCH/STATUS/SORT and read-only JMAP/webapi GETs.
- Do **not** add a separate in-process mutex for account serialization — the
  advisory lock is the only lock.

---

## Writing to the change-log

State changes go through `pgTx.record` / `pgTx.flush` (`storage/postgres/account.go`),
which append `Change` entries to `changelog` and advance `accounts.changelog_seq`
**in the same transaction** as the projection updates. Do not write projection tables
(`messages`, `mailboxes`) without also recording the corresponding change — the log
and the load-bearing tables are co-equal sources of truth written atomically.

The log is the source of truth for **ordering and change-notification**, not for
**content**: `ChangeAddUID` carries `mailbox_id/uid/modseq/flags/keywords` but not
`blob_ref/size/msg_prefix` — you cannot rebuild `messages` from the log alone. See
the "边界(不要误读)" section of `docs/architecture.md`.

---

## Schema: DDL split by concept, embedded and idempotent

Schema lives in `storage/postgres/schema/NN_*.sql`, `go:embed`-ed via
`storage/postgres/store.go` and applied at `Open`. Files are ordered and
concept-scoped:

```
01_directory  02_changelog(★spine)  03_projections  04_queue
05_deliverability  06_reports_antiabuse  07_apikeys  08_leader_lease  09_junkfilter
```

- Every statement is **idempotent**: `CREATE TABLE IF NOT EXISTS`,
  `CREATE INDEX IF NOT EXISTS`. Migrations re-run safely on every boot.
- Tables that carry per-account data are **HASH-partitioned by `account_id`**
  (see `02_changelog.sql`) with the PK leading on the shard key — this is the
  open-source equivalent of Citus distribution. New tables holding account data
  should follow the same pattern.
- Add a new numbered file (or extend the matching concept file); keep the spine
  (`02_changelog.sql`) minimal and clearly marked.

---

## Tests need REAL infra — a skipped test is not a passing test

`make test` runs `go test -p 1 ./...`. **`-p 1` is mandatory**: packages share one
Postgres test database, so parallel packages corrupt each other.

- Default test DSN:
  `postgres://octo_mail:octo_mail@localhost:55432/octo_mail`
  (constant `testDSN` in `storage/postgres/e2e_test.go`).
- ~94 test files call `t.Skip`/`t.Skipf` when infra is absent. A green run with no
  DB means tests were **skipped, not passed** — always confirm the DB is up.
- Test setup is `Open(ctx, testDSN, bs)` then navigate the directory graph for an
  account; follow existing `*_test.go` in `storage/postgres/` rather than inventing
  a helper. Start Postgres with the command printed in `e2e_test.go`'s skip message.

---

## Anti-patterns

- A write transaction that runs before `pg_advisory_xact_lock($1)` — race on
  seq/uid/modseq across nodes.
- Truncating `account_id` to fit an int32 advisory key — always pass the full id.
- Mutating `messages`/`mailboxes` without an accompanying `Change` in the same tx.
- Non-idempotent DDL (bare `CREATE TABLE`) — breaks re-boot.
- Running `go test` without `-p 1`, or reporting "tests pass" from a run where the
  DB was down (everything skipped).
