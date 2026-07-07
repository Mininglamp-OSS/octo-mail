# Contributing to octo-mail

Thanks for your interest in improving octo-mail. This document explains how to
build, test, and submit changes.

By contributing, you agree that your contributions will be licensed under the
project's [Apache License 2.0](LICENSE).

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md); by participating,
you are expected to uphold it.

## Getting started

Requirements:

- **Go 1.25+**
- **Docker** (for the Compose stack, or for a local PostgreSQL + MinIO)

Dependencies are vendored under `vendor/`, so the project builds offline —
`go build` uses `-mod=vendor` automatically. There is no need to run
`go mod download`.

```sh
git clone https://github.com/Mininglamp-OSS/octo-mail.git
cd octo-mail
make build          # compiles the webui, then builds ./... (static, CGO_ENABLED=0)
```

## Building and testing

The `Makefile` is the entry point for everyday tasks:

```sh
make build          # webui + go build ./...
make test           # go test -p 1 ./...
make vet            # go vet ./...
make fmt            # gofmt the tree
make frontend       # compile webui TypeScript -> committed JS
```

Tests run against **real** infrastructure — PostgreSQL and MinIO (S3) — plus the
unmodified upstream protocol clients. Use `-p 1`: packages share a single test
database, so parallel package execution would race.

Point the tests at a database with `OCTO_MAIL_DSN` (default
`postgres://…@localhost:55432`). The quickest way to get one:

```sh
docker compose up -d postgres minio
make test
```

Some suites are gated behind the `e2e` build tag and drive the full deployed
stack over the wire:

```sh
docker compose up -d --build
go test -tags e2e ./e2e/
```

Before opening a pull request, make sure the following pass locally:

```sh
make fmt && make vet && make test
```

## Making changes

### Architectural boundaries

octo-mail's dependency direction is strict and one-way:

```
protocol → core interfaces → storage implementation → substrate (PostgreSQL/S3)
```

Please respect it:

- **`protocol/*` packages depend on `core` interfaces only** — never import
  `storage/*` directly.
- Code above the interface line (`core`, `protocol`) must not assume Postgres or
  S3 exists; the substrate must not assume IMAP/JMAP/SMTP exists.
- `mailflow`, `security`, and `ops` may cut across layers but must not depend on
  `protocol`.

See [docs/architecture.md](docs/architecture.md) for the full model, including
the change-log spine and the single-writer concurrency invariants. Changes that
touch the change-log (`storage/postgres/schema/02_changelog.sql`) or the
projection tables deserve extra care and a clear description of why the
ordering/consistency guarantees still hold.

### Coding style

- Format with `gofmt` (`make fmt`) and keep `go vet` clean (`make vet`).
- Match the conventions of the surrounding code — naming, comment density, and
  error handling.
- Add tests for new behavior. Prefer tests that exercise the real storage layer,
  consistent with the existing suites.
- Keep protocol algorithms in the reused upstream libraries; contribute
  kernel/storage/server logic here rather than reimplementing wire protocols.

### Commits

- Write clear, imperative commit messages. Conventional-commit prefixes
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) are used throughout the
  history and appreciated.
- Keep each commit focused and self-contained; the tree should build and test at
  every commit.

## Submitting a pull request

1. For anything substantial, **open an issue first** to discuss the approach —
   it saves rework.
2. Create a topic branch from `main`.
3. Make your change with tests; run `make fmt && make vet && make test`.
4. Open a pull request against `main` with a description of **what** changed and
   **why**, and note any architectural or schema implications.
5. Address review feedback by pushing additional commits (the branch is squashed
   or rebased at merge time as appropriate).

## Reporting bugs and requesting features

- **Bugs / features:** open a GitHub issue with steps to reproduce, expected vs.
  actual behavior, and version/commit information.
- **Security vulnerabilities:** do **not** open a public issue — follow the
  process in [SECURITY.md](SECURITY.md).

## License

octo-mail is licensed under the Apache License 2.0. It reuses the
[mox](https://github.com/mjl-/mox) protocol libraries under the MIT License;
third-party attributions are recorded in [NOTICE](NOTICE).
