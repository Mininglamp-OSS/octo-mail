# octo-mail

Change-log-centric, multi-tenant mail server kernel in Go. See `README.md` for the
feature matrix and `docs/architecture.md` for the design (directory layout = architecture).

## Commands
```sh
make build        # frontend (tsc) + CGO_ENABLED=0 go build ./...
make test         # go test -p 1 ./...  (MUST be -p 1: packages share one Postgres DB)
make vet          # go vet ./...
make fmt          # gofmt -w -s across all source dirs
make frontend     # webui/assets: tsc -p tsconfig.json
go run ./cmd/octo-mail   # 12-factor env config; see cmd/octo-mail/config.go
```

## Gotchas
- **mox dependency**: reuses mox's pure-protocol packages (`smtp`/`dns`/`dkim`/`spf`/
  `dmarc`/`scram`/`message`/...) as a version-pinned Go module (`github.com/mjl-/mox`
  in `go.mod`), vendored under `vendor/`. Builds offline and self-contained
  (`-mod=vendor` is automatic). Bump deps with
  `go get <mod>@<ver> && go mod tidy && go mod vendor`. For local mox co-development,
  create a throwaway `go.work` with `use ../mox` (gitignored); do not reintroduce a
  `replace` directive into `go.mod`.
- **Tests need real infra**: PostgreSQL 17 at `OCTO_MAIL_DSN` (default `localhost:55432`)
  + MinIO/S3. ~94 test files `t.Skip` when infra is absent — a green run with no DB
  means tests were skipped, not passed. Always run with `-p 1` (shared test database).
- **Committed frontend JS**: `webui/assets/*.ts` is source; `*.js` is committed and
  `go:embed`ed into the binary. Edit the `.ts` and run `make frontend`; never hand-edit `.js`.
- **Naming separators differ by context** (module path allows `-`, identifiers don't):
  module/import `github.com/Mininglamp-OSS/octo-mail`, env vars `OCTO_MAIL_*`,
  Prometheus metrics `octo_mail_*`, Postgres DSN user/db `octo_mail`.

## Architecture (one-liner)
Per-account append-only change-log is the source of truth (`schema/02_changelog.sql` ★);
mailbox state is a rebuildable projection; IMAP/JMAP/SMTP are consumers. Dependency
direction: `protocol → core interfaces → storage impl → substrate (PG/S3)`. Details in
`docs/architecture.md`.
