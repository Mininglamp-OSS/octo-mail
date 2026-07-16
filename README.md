# octo-mail

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8.svg?logo=go&logoColor=white)](go.mod)
[![Protocols](https://img.shields.io/badge/protocols-IMAP4rev2%20%C2%B7%20JMAP%20%C2%B7%20SMTP%20%C2%B7%20REST-informational.svg)](#protocols--surfaces)

**A change-log-centric, multi-tenant, horizontally-scalable mail server kernel, written in Go.**

octo-mail is built around one idea: an **append-only, per-account change-log is the
source of truth**. Mailbox state is a projection of that log; IMAP, JMAP, SMTP, and a
REST API are its consumers; replication and HA simply run the log. Nodes are stateless
and sit on **PostgreSQL + S3**, so the system scales horizontally and isolates tenants
structurally rather than by convention.

Protocol algorithms (DKIM/SPF/DMARC, SMTP/IMAP wire, SASL/SCRAM, DNS) are **reused
unmodified** from [mox](https://github.com/mjl-/mox) as a version-pinned, vendored Go
module — octo-mail contributes the multi-tenant kernel, the storage layer, and the
server surfaces on top.

---

## Table of contents

- [Highlights](#highlights)
- [Protocols & surfaces](#protocols--surfaces)
- [Quick start](#quick-start)
- [Building from source](#building-from-source)
- [Configuration](#configuration)
- [Clients](#clients)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Highlights

- **Change-log spine.** One monotonic per-account sequence drives IMAP
  `MODSEQ`/`CONDSTORE`, JMAP `state`, and `QRESYNC VANISHED` from a single ordered
  source — the same replay renders every surface consistently and powers cross-node
  notification and replication.
- **Structural multi-tenancy.** Tenant isolation is enforced at the type level
  (compile-time object-reachability), not by runtime filters — an account handle can
  only ever reach its own data.
- **Stateless, horizontally scalable.** No node owns state or the queue. Per-account
  `pg_advisory_xact_lock` serializes writes within an account while keeping all
  accounts fully parallel (tables partitioned by `account_id`).
- **PostgreSQL + S3.** Native schema with `account_id` partitioning; message bodies are
  content-addressed in S3-compatible object storage (SigV4, ranged GET).
- **Production mail flow.** Inbound authentication (SPF/DKIM/DMARC/iprev/DNSBL) with
  reputation, greylisting, and a per-account Bayesian junk filter; an append-only
  outbound queue with leased delivery, exponential backoff, DANE/MTA-STS, RFC 3461
  DSNs, and auto-suppression on hard bounce.
- **Operable by default.** Prometheus metrics, leader election with crash failover,
  DMARC/TLS-RPT report ingestion, ACME/autotls, and privilege-separated port binding.

## Protocols & surfaces

| Surface | Details |
|---|---|
| **IMAP4rev2 / rev1** | CONDSTORE, QRESYNC, REPLACE, COMPRESS, METADATA, BINARY, UIDONLY, QUOTA, IDLE, NOTIFY, ESEARCH, SORT, THREAD, OBJECTID, CATENATE, URLAUTH, and more |
| **JMAP** (RFC 8620/8621) | Email / Mailbox / Thread / Identity / SearchSnippet / EmailSubmission / VacationResponse; multi-mailbox model; EventSource push |
| **SMTP** | SPF/DKIM/DMARC/DNSBL auth, DANE/MTA-STS outbound, SIZE/PIPELINING/8BITMIME/CHUNKING/BURL/DSN/FUTURERELEASE |
| **REST WebAPI** (`/webapi/v0`) | Resource-oriented HTTP/JSON for programmatic mail: messages (list/get/raw/send/reply/reply-all/forward/flag/delete), threads, drafts, mailboxes, suppressions. Account-scoped API-key auth (`Authorization: Bearer omk_…`); message ids (`E<n>`) shared with JMAP |
| **SASL** | SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (TLS channel binding) on IMAP and SMTP submission |
| **Webmail** | Browser client (strict TypeScript → compiled JS → `go:embed`) |

## Quick start

The fastest way to see a full stack — octo-mail + PostgreSQL + MinIO (S3) — is Docker
Compose:

```sh
docker compose up -d --build
```

This publishes SMTP `2525`, submission `5587`, IMAP `1143`, JMAP + webmail `8090`, and
admin + `/metrics` + `/healthz` `8091` on localhost.

Provision a tenant, domain, account, and address through the admin API, then mint an
account API key and drive the REST surface:

```sh
ADMIN=http://localhost:8091
TOKEN=e2e-admin-token   # docker-compose dev token; change for any real deployment

curl -s -XPOST $ADMIN/admin/tenants   -H "Authorization: Bearer $TOKEN" -d '{"name":"acme"}'
curl -s -XPOST $ADMIN/admin/domains   -H "Authorization: Bearer $TOKEN" -d '{"tenant_id":1,"domain":"acme.test"}'
curl -s -XPOST $ADMIN/admin/accounts  -H "Authorization: Bearer $TOKEN" -d '{"tenant_id":1,"name":"alice"}'
curl -s -XPOST $ADMIN/admin/addresses -H "Authorization: Bearer $TOKEN" -d '{"tenant_id":1,"domain":"acme.test","localpart":"alice","account":"alice"}'

# Mint an account-scoped API key (omk_…); the secret is shown once.
KEY=$(docker compose exec -T octo-mail octo-mail apikey create alice@acme.test cli | grep -o 'omk_[a-z0-9_]*')

# Use the REST WebAPI.
curl -H "Authorization: Bearer $KEY" http://localhost:8090/webapi/v0/mailboxes
```

> **Note.** The Compose file ships throwaway development credentials
> (`e2e-admin-token`, `minioadmin`). They are for local evaluation only — never reuse
> them in a real deployment.

## Building from source

Requires **Go 1.25+**. Dependencies are vendored, so the build is offline and
self-contained (`go build` uses `-mod=vendor` automatically).

```sh
make build          # compile the webui, then build ./... (CGO_ENABLED=0 static binary)
make test           # go test -p 1 ./... — needs a PostgreSQL (see below)
make vet && make fmt
```

Run a node directly:

```sh
go run ./cmd/octo-mail serve      # 12-factor env config; see cmd/octo-mail/config.go
```

Tests run against **real** PostgreSQL and MinIO plus the unmodified upstream protocol
clients; use `-p 1` because packages share a single test database (default DSN
`postgres://…@localhost:55432`, override with `OCTO_MAIL_DSN`).

To bump a dependency: `go get <mod>@<ver> && go mod tidy && go mod vendor`.

## Configuration

octo-mail is configured entirely through environment variables (12-factor); there is no
config file. The authoritative list lives in
[`cmd/octo-mail/config.go`](cmd/octo-mail/config.go). The essentials:

| Variable | Purpose |
|---|---|
| `OCTO_MAIL_DSN` | PostgreSQL connection string (**required**) |
| `OCTO_MAIL_HOSTNAME` | Server hostname (HELO / Message-ID / TLS) |
| `OCTO_MAIL_S3_ENDPOINT` / `_REGION` / `_BUCKET` / `_ACCESS` / `_SECRET` | S3-compatible blob store; falls back to `OCTO_MAIL_BLOB_DIR` for local FS |
| `OCTO_MAIL_SMTP_ADDR` / `_SUBMISSION_ADDR` / `_IMAP_ADDR` / `_JMAP_ADDR` / `_ADMIN_ADDR` | Listen addresses per surface |
| `OCTO_MAIL_ADMIN_TOKEN` | Bearer token guarding the admin API |
| `OCTO_MAIL_NODE_ID` | Unique node identity for HA leader election |

Anti-abuse, queue, ACME, and deliverability knobs (`OCTO_MAIL_REJECT_DMARC`,
`OCTO_MAIL_GREYLIST`, `OCTO_MAIL_QUEUE_BACKOFF`, `OCTO_MAIL_ACME_HOSTS`, …) are
documented alongside their defaults in `config.go`.

Built-in ACME runs single-node over tls-alpn-01 by default. For the stateless
multi-node cluster, set `OCTO_MAIL_ACME_DNS_WEBHOOK_URL` (a provider-neutral,
HMAC-signed DNS solver webhook): the elected leader then issues/renews over DNS-01
into shared Postgres and every node serves from it — no shared proxy required.

The `octo-mail` binary also exposes operational subcommands:
`serve`, `passwd`, `apikey`, `gendkim`, `export`, `import`.

## Clients

- **[octo-cli](https://github.com/Mininglamp-OSS/octo-cli)** — the official CLI. Its
  `mail` commands are generated from an OpenAPI spec and target the REST WebAPI, using
  an `omk_…` account key as the bearer credential
  (`octo mail send|list|get|reply|flag|…`).
- **Any JMAP or IMAP client** — standard clients work directly against ports `8090`
  (JMAP) and `143`/`1143` (IMAP) with SCRAM-SHA-256 credentials.
- **Webmail** — the embedded browser client is served under `/webmail`.

## Architecture

The top-level directory tree mirrors the architecture — reading `ls` is reading the
design. See **[docs/architecture.md](docs/architecture.md)** for the full write-up of
the change-log spine, the single-writer concurrency model, and the boundary between
what the log owns (ordering and change notification) and what the projection tables own
(content).

## Project layout

```
cmd/          single stateless node binary (serve + operational subcommands)
core/         source-of-truth interfaces (store) + tenant-isolation contracts (directory)
storage/      core implemented on PostgreSQL (schema, change-log, projections) + S3/FS blobs
projection/   read-only materialized-view workers (FTS, threads), rebuildable from messages
protocol/     one package per surface, bound only to core: imapd · jmapd · smtpd · webapi
mailflow/     inbound pipeline, submission, outbound queue, autoreply, deliverability
security/     auth (argon2id + SCRAM), ACME/autotls, privilege separation
ops/          Prometheus metrics, HA leader election, report ingestion, admin API, mbox tools
webui/        browser webmail (TypeScript → compiled JS → go:embed)
junkfilter/   per-account Bayesian junk filter
docs/         architecture documentation
```

Dependencies flow one way: `protocol → core interfaces → storage implementation →
substrate (PostgreSQL/S3)`. Code above the interface line has no knowledge of Postgres
or S3; the substrate has no knowledge of IMAP.

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes
before sending a pull request, and see **[CONTRIBUTING.md](CONTRIBUTING.md)** for
the full workflow. Before submitting:

```sh
make fmt && make vet && make test
```

Keep changes consistent with the surrounding code and the architectural
boundaries described above (protocol packages depend on `core` interfaces only,
never on `storage`).

## Security

Please **do not** file public issues for security vulnerabilities. See
**[SECURITY.md](SECURITY.md)** — report privately via
[GitHub security advisories](https://github.com/Mininglamp-OSS/octo-mail/security/advisories/new).

## License

octo-mail is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).

It reuses the [mox](https://github.com/mjl-/mox) protocol libraries under the MIT
License; third-party attributions are recorded in [NOTICE](NOTICE), and each vendored
module retains its upstream license under `vendor/`.
