# Backend Development Guidelines

Coding guidance for octo-mail — a change-log-centric, multi-tenant mail server
kernel in Go. Read `CLAUDE.md` and `docs/architecture.md` first: **the directory
layout _is_ the architecture**, and these specs assume that map.

The one-liner: a per-account append-only change-log is the source of truth
(`storage/postgres/schema/02_changelog.sql` ★); mailbox state is a rebuildable
projection; IMAP/JMAP/SMTP/WebAPI are consumers. Dependencies flow one way:
`protocol → core interfaces → storage impl → substrate (PG/S3)`.

---

## Guidelines Index

| Guide | Covers |
|-------|--------|
| [Directory Structure](./directory-structure.md) | Layer map, dependency direction, where new code goes |
| [Database Guidelines](./database-guidelines.md) | pgx, the per-account advisory lock, change-log writes, schema, partitioning, tests need real infra |
| [Error Handling](./error-handling.md) | `fmt.Errorf("...: %w", err)` wrapping, sentinel errors, `errors.Is`, no `panic` in product code |
| [Logging Guidelines](./logging-guidelines.md) | Injected `*slog.Logger`, `WarnContext`, structured key/value pairs |
| [Quality Guidelines](./quality-guidelines.md) | mox reuse boundary, committed frontend JS, naming separators, `make` targets, tenant isolation |

---

## Cross-cutting rules (apply everywhere)

- **Never reverse the dependency direction.** Code above the interface line
  (`core/`, `protocol/`) must not import `storage/postgres` or know Postgres/S3
  exists. See [Directory Structure](./directory-structure.md).
- **Tenant isolation is structural, not a per-query filter.** You obtain an
  `store.Account` only by navigating a `directory.TenantScope` or
  `directory.InboundTarget` — never by global name/id. See
  [Quality Guidelines](./quality-guidelines.md).
- **Protocol algorithms are reused from mox, not reimplemented.** DKIM/SPF/DMARC/
  SMTP-wire/SASL/SCRAM/DNS come from the vendored `github.com/mjl-/mox` module.
  The server surfaces are new code. See [Quality Guidelines](./quality-guidelines.md).
- **`make test` with `-p 1` is mandatory** and needs real PostgreSQL + MinIO/S3.
  A green run with no DB means tests were **skipped**, not passed. See
  [Database Guidelines](./database-guidelines.md).

All documentation is written in English.
