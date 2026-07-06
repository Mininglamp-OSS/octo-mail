# octo-mail

A change-log-centric, multi-tenant, horizontally-scalable mail server kernel in Go.
One append-only per-account change-log is the source of truth; mailbox state is its
projection; IMAP / JMAP / SMTP are its consumers; replication / HA run the log.
Protocol libraries are reused from [mox](https://github.com/mjl-/mox), imported as a
version-pinned Go module dependency (see `go.mod`).

- **IMAP4rev2** + **IMAP4rev1** + CONDSTORE / QRESYNC / REPLACE / COMPRESS / METADATA / BINARY / UIDONLY / QUOTA / IDLE / NOTIFY / ESEARCH / SEARCHRES / WITHIN / STATUS=SIZE / MULTIAPPEND / ID / LITERAL+ / UTF8=ACCEPT / APPENDLIMIT / LIST-EXTENDED / SPECIAL-USE / CREATE-SPECIAL-USE / LIST-METADATA / SORT / THREAD / SAVEDATE / MULTISEARCH / PREVIEW / OBJECTID / CATENATE / URLAUTH / INPROGRESS
- **SASL**: SCRAM-SHA-256 + SCRAM-SHA-256-PLUS (TLS channel binding), on both IMAP and SMTP submission
- **JMAP** (RFC 8620/8621): Email/Mailbox/Thread/Identity/SearchSnippet/EmailSubmission/VacationResponse, multi-mailbox model, EventSource push
- **REST WebAPI** (`/webapi/v0`): resource-oriented HTTP/JSON for programmatic mail — messages (list/get/raw/send/reply/reply-all/forward/flag/delete), threads, drafts, mailboxes, suppressions; account-scoped API-key auth (`Authorization: Bearer omk_…`), shared `E<n>` message ids with JMAP. Consumed by [octo-cli](https://github.com/Mininglamp-OSS/octo-cli)'s `mail` commands.
- **SMTP**: SPF/DKIM/DMARC/DNSBL auth, bayesian junk, reputation/greylist/subjectpass/ruleset, DANE/MTA-STS outbound, SIZE/PIPELINING/8BITMIME/CHUNKING/BURL/DSN(RET/ENVID/NOTIFY/ORCPT)/ENHANCEDSTATUSCODES/LIMITS/FUTURERELEASE, VRFY/EXPN/HELP
- **Outbound queue**: log-spine design (append-only `queue_log` source of truth + mutable projection for the due-scan, like the rest of octo-mail) with a lease for delivery ownership (no node owns the queue); exponential backoff + jitter, permanent-5xx fast-fail (no wasted retries), hold/unhold + auto-hold rules, per-message RequireTLS override, admin ops (list/kick/schedule/schedule-at/hold/drop/fail/requiretls), per-attempt result history + retired listing (views over the log), retention cleanup, RFC 3461 DSN handling (NOTIFY/RET/ENVID/ORCPT honored), delayed-delivery + permanent-failure DSNs (null-sender double-bounce guard), auto-suppression on hard bounce, Prometheus queue metrics (delivery-duration histogram + depth gauge)
- **PostgreSQL** (native schema + account_id partitioning) + **S3** (content-addressed bodies)
- Native multi-tenancy (compile-time object-reachability isolation), stateless nodes, PG streaming-replication HA

## Layout

The top-level directory tree mirrors the architecture — see [docs/architecture.md](docs/architecture.md).

## Build & test

```sh
go build ./...                 # CGO_ENABLED=0 static binary
go test -p 1 ./...             # needs a Postgres at OCTO_MAIL_DSN (default localhost:55432)
make frontend                  # compile webui TypeScript -> committed JS
```

Tests use real PostgreSQL 17 + real MinIO + the reused, unmodified protocol clients;
run with `-p 1` (packages share one test database).

Dependencies are vendored under `vendor/`, so the repo builds offline and
self-contained (`go build` uses `-mod=vendor` automatically). To bump a
dependency: `go get <mod>@<ver> && go mod tidy && go mod vendor`.

## Run

```sh
go run ./cmd/octo-mail            # 12-factor env config; see cmd/octo-mail/config.go
```

## License

octo-mail is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
It reuses the [mox](https://github.com/mjl-/mox) protocol libraries under the MIT
License; third-party attributions are in [NOTICE](NOTICE).
