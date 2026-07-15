# Directory Structure

> In octo-mail the directory layout **is** the architecture. `ls` the top level
> and you are reading the design. Full narrative: `docs/architecture.md`.

---

## Layer map

```
cmd/octo-mail/   single stateless node binary: main + serve assembly + ops subcommands
                 (config.go = 12-factor env config; admin.go; main.go)

core/            SOURCE-OF-TRUTH INTERFACES — depends on no protocol or backend
  store/           kernel interfaces (Account, Tx, MessageQuery) + shape types
                   (Message, Flags, UID, ModSeq, Change, Comm)
  directory/       structural tenant-isolation contracts
                   (Directory, TenantScope, InboundTarget)
  addr/            address helpers

storage/         IMPLEMENTATION — sits core's interfaces on PG + S3
  postgres/        store impl: advisory-lock write tx, changelog codec, projections,
                   coordinator (LISTEN/NOTIFY); schema/*.sql is go:embed-ed
  blob/            message bodies: fs + s3 (SigV4, content-addressed, ranged GET)

projection/      DERIVED — read-only materialized-view workers (FTS, threads),
                 rebuildable from the messages load-bearing table

protocol/        CONSUMERS — one package per surface, bound only to core interfaces
  imapd/ jmapd/ smtpd/ webapi/

mailflow/        mail in/out pipeline
  inbound/ submit/ queue/ autoreply/ deliverability/

security/        cross-cutting: auth/ (argon2id + SCRAM), acme/, privsep/
ops/             obs/ (metrics) ha/ reportdb/ webadmin/ mailboxops/
webui/           browser webmail (TS → committed JS → go:embed)
junkfilter/      per-account Bayesian filter (wraps a bayesian lib)
```

---

## Dependency direction (the one rule you cannot break)

`protocol → core interfaces → storage impl → substrate (PG/S3)`

- Code **above the interface line** (`core/`, `protocol/`) has no knowledge of
  Postgres or S3. It imports `core/store` and `core/directory` interfaces only.
- The **substrate** (`storage/postgres`, `storage/blob`) has no knowledge of IMAP,
  JMAP, or SMTP.
- `mailflow/`, `security/`, `ops/` are cross-cutting but must **not** depend back on
  `protocol/`.

`core/store/reuse_check.go` compile-time-proves the mox protocol library binds to
these interfaces — that file is the canary for the boundary.

### How to tell where new code goes

| You are adding… | It belongs in… |
|-----------------|----------------|
| A new stored operation on an account/mailbox/message | interface method in `core/store/account.go`, implemented in `storage/postgres/` |
| A new IMAP/JMAP/SMTP command or REST route | `protocol/<surface>/`, calling only `core/store` + `core/directory` |
| A new inbound decision, queue behavior, or delivery step | `mailflow/<stage>/` |
| A new derived/materialized view | `projection/` (must be rebuildable from `messages`) |
| A new SQL table/column | a `storage/postgres/schema/NN_*.sql` file (see Database Guidelines) |
| A new operational subcommand or admin endpoint | `cmd/octo-mail/` or `ops/webadmin/` |

---

## Naming separators differ by context

The module path allows `-`; Go identifiers and DB/Prometheus names do not:

- module / import path: `github.com/Mininglamp-OSS/octo-mail`
- env vars: `OCTO_MAIL_*`
- Prometheus metrics: `octo_mail_*` (e.g. `ops/obs/obs.go`)
- Postgres DSN user/db: `octo_mail`

---

## Anti-patterns

- A `protocol/` file importing `storage/postgres` or referencing `pgx` — reverses
  the dependency direction.
- Putting a stored operation directly in a protocol handler instead of behind a
  `core/store.Account` method.
- A `projection/` view that cannot be rebuilt from the `messages` table (only FTS
  and thread views are truncate-and-rebuild; see `docs/architecture.md`).
