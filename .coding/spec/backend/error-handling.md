# Error Handling

octo-mail uses idiomatic Go error handling: values, wrapping, and sentinels. No
`panic` in product code, no custom error framework.

---

## Wrap with `fmt.Errorf("context: %w", err)`

The dominant pattern (100+ call sites) is to add context and preserve the chain with
`%w`:

```go
if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, a.id); err != nil {
    return fmt.Errorf("advisory lock: %w", err)
}
```

- Prefix with a short, lowercase, colon-terminated context describing the operation.
- Use `%w` (not `%v`) so callers can `errors.Is`/`errors.As` through the chain.
- Wrap at layer boundaries where the added context helps; don't double-wrap the same
  frame.

Reference: `storage/postgres/account.go`, `cmd/octo-mail/config.go`.

---

## Sentinel errors for conditions callers branch on

Define an exported (or package-private) `var Err… = errors.New(...)` when callers
must distinguish a specific condition, and compare with `errors.Is`:

- `core/store/account.go` — `ErrOverQuota` (permanent: reject, don't defer).
- `storage/blob/blob.go` — `ErrBadRef`, `ErrNotFound`.
- `mailflow/submit/deliverer.go` — `ErrSuppressed`.
- `mailflow/deliverability/iprouter.go` — `ErrNoSourceIP`.
- package-private in `storage/postgres/errors.go` — `errNotFound`, `errUnknownChange`.

Name sentinels with the package meaning baked into the message
(`"blob: not found"`, `"postgres: not found"`), so a wrapped error is legible even
without the type. `errors.Is` (15 sites) and `errors.As` (7 sites) are the
inspection tools — never string-match on `err.Error()` to detect a condition.

---

## Never `panic` in product code

Non-test product code has **zero** `panic` calls. Return an error instead. Startup
misconfiguration is surfaced as an error from validation (`cmd/octo-mail/config.go`:
`checkVERPConfig`, `checkReporterConfig`, `validate`) and turned into a clean exit by
`main`, not a panic. `panic` is acceptable only in tests / truly-unreachable
invariants, and even then prefer `t.Fatal`.

Config validation refuses fail-open security holes loudly at startup — e.g. a bounce
domain with no VERP signing key returns a descriptive error rather than silently
accepting forgeable tokens. Follow that model for new config: validate and refuse,
don't warn-and-continue, when the wrong value is a security or correctness hazard.

---

## Anti-patterns

- `fmt.Errorf("...: %v", err)` where the caller needs `errors.Is` — loses the chain.
- Detecting a condition via `strings.Contains(err.Error(), "...")` instead of a
  sentinel + `errors.Is`.
- `panic` on a recoverable/expected failure in product code.
- Swallowing an error (`_ = doThing()`) on a path that can fail meaningfully.
