# Logging Guidelines

octo-mail logs with the standard library `log/slog` only. There is no third-party
logging dependency (no zap, no logrus).

---

## Inject a `*slog.Logger`, don't reach for a global

Servers and workers hold a `Log *slog.Logger` field, set at assembly time in
`cmd/octo-mail`. Examples: `protocol/jmapd/server.go`, `protocol/webapi/webapi.go`,
`ops/webadmin/webadmin.go`, `mailflow/submit/deliverer.go`,
`mailflow/deliverability/ob_webhookworker.go`.

- Prefer the injected logger (`s.Log`, `w.Log`) over `slog.Default()`.
- When a logger may be nil at a leaf, guard once and fall back:
  ```go
  if log == nil {
      log = slog.Default()
  }
  ```
  (see `mailflow/submit/deliverer.go`). Don't scatter nil-checks everywhere.

---

## Structured key/value pairs, and `…Context` when you have a ctx

Log a stable message string followed by `key, value` pairs — never format the values
into the message:

```go
w.Log.WarnContext(ctx, "webhook state update failed", "op", op, "event", id, "err", err)
s.Log.WarnContext(r.Context(), "webapi internal error",
    "method", r.Method, "path", r.URL.Path, "err", err)
```

- Use the `Context` variants (`InfoContext`/`WarnContext`/`ErrorContext`) whenever a
  `context.Context` is in scope so trace/cancel metadata propagates.
- Pass the error under the `"err"` key.
- Keep the message a short constant so logs are groupable; put the varying data in
  the key/value tail.

---

## Level guidance (as used in the codebase)

- `Info` — normal lifecycle facts (`log.Info("blob store", "backend", "s3", ...)`).
- `Warn` — recoverable anomalies and misconfigurations that don't stop the process
  (health-check failure, lease possibly lost, quarantining a message with an
  unreadable blob — see `projection/threads.go`).
- `Error` — genuine failures worth alerting on.
- Startup config that is dangerous but explicitly opted into is `Warn` + continue;
  config that is unsafe is a returned **error**, not a log line (see
  [Error Handling](./error-handling.md)).

---

## Anti-patterns

- Introducing a logging library — use `log/slog`.
- `fmt.Sprintf`-ing values into the log message instead of key/value pairs.
- Using `Info`/`Warn` without the `Context` variant when a ctx is available.
- Reaching for `slog.Default()` in code that already has an injected `Log` field.
