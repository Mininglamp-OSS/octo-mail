# Quality Guidelines

Project-specific standards that catch the mistakes most likely to bite in octo-mail.
General Go hygiene (`make vet`, `make fmt` = `gofmt -w -s`) is assumed.

---

## The mox reuse boundary — reuse algorithms, don't reimplement

Pure-protocol algorithms come from the vendored `github.com/mjl-/mox` module
(`smtp`/`dns`/`dkim`/`spf`/`dmarc`/`scram`/`message`/…), pinned in `go.mod` and
committed under `vendor/`. Builds are offline (`-mod=vendor` is automatic).

- **Do not reimplement** DKIM signing, SPF/DMARC evaluation, SMTP/IMAP wire parsing,
  SASL/SCRAM, or DNS resolution — bind the mox package.
  `core/store/reuse_check.go` compile-time-proves those libraries bind to octo-mail's
  interfaces; keep it green.
- The **server surfaces are octo-mail's own code**: `protocol/{imapd,smtpd,jmapd,
  webapi}` are thin consumers written against `core` interfaces. mox's own
  imap/smtp *servers* are **not** reused; `jmapd` is fully original.
- Bump deps with `go get <mod>@<ver> && go mod tidy && go mod vendor`. For local mox
  co-development use a throwaway `go.work` (`use ../mox`, gitignored) — **never**
  reintroduce a `replace` directive into `go.mod`.

---

## Tenant isolation is structural — never take an id/name shortcut

Isolation is enforced by the object graph, not by remembering to filter. The **only**
way to reach a `store.Account` is by navigating from a capability you were granted:

- `directory.TenantScope` (from authentication) — `Account`, `AccountForAddress`,
  `AccountForID` all resolve **within that one tenant**; an id from another tenant
  matches nothing.
- `directory.InboundTarget` (from `ResolveInbound`, the only unauthenticated
  resolver) — can `Deliver`/`DeliverTo` one account and nothing else.

Rules (see `core/directory/directory.go`):

- Do **not** add a global, id-taking, tenant-crossing accessor anywhere. If you need
  an account, thread the scope/target through, don't look it up by bare name/id.
- A handler holding tenant A's scope must have no reference through which to name
  tenant B's objects. The isolation tests in `storage/postgres/isolation_test.go`
  and `isolation_authz_test.go` guard this — extend them when you touch auth/resolve.
- Tenant-shared resources (e.g. the content-addressed blob store) are scoped by the
  authenticated `TenantID()`, never a client-supplied id.

---

## Committed frontend JS — edit `.ts`, run `make frontend`

`webui/assets/*.ts` is source; the committed `*.js` is `go:embed`-ed into the binary.

- **Never hand-edit the `.js`.** Edit the `.ts` and run `make frontend` (`tsc -p
  tsconfig.json`); commit the regenerated `.js`.
- `make build` runs the frontend build before `CGO_ENABLED=0 go build ./...`.

---

## Configuration is 12-factor env vars

Config is read from `OCTO_MAIL_*` environment variables in
`cmd/octo-mail/config.go::loadConfig`, using the local helpers `envDefault`,
`envInt64`, `envDuration`, `envFloat`, `envLower`, `parseDomainList`. Add new config
by extending the `config` struct + `loadConfig`, with a sensible default, and validate
it in `validate`/`check*` if a wrong value is unsafe. Naming: env `OCTO_MAIL_*`,
metrics `octo_mail_*`, DSN user/db `octo_mail` (see Directory Structure).

---

## Commands

```sh
make build     # frontend (tsc) + CGO_ENABLED=0 go build ./...
make test      # go test -p 1 ./...  (MUST be -p 1: packages share one Postgres DB)
make vet       # go vet ./...
make fmt       # gofmt -w -s across all source dirs
make frontend  # webui/assets: tsc -p tsconfig.json
```

Before reporting work complete: `make fmt`, `make vet`, and `make test` against a
**live** Postgres + S3/MinIO (a skipped run is not a passing run — see
[Database Guidelines](./database-guidelines.md)).

---

## Anti-patterns

- Reimplementing a protocol algorithm that mox already provides.
- A `replace` directive in `go.mod` (use `go.work` for local mox work).
- Hand-editing `webui/assets/*.js`.
- Any account lookup that crosses tenants by id/name instead of via a `TenantScope`/
  `InboundTarget`.
- Adding config via ad-hoc `os.Getenv` scattered outside `loadConfig` without a
  default or validation.
