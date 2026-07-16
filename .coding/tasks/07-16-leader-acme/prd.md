# Leader-gated cluster ACME issuance (shared cert cache)

Tracks GitHub issue #32 — the full multi-node fix (option B) for H17 (#19), which
shipped as documented single-node only (option C).

## Goal

Make octo-mail's built-in ACME safe to run across the stateless multi-node cluster:
exactly one node (the leader) issues/renews certificates into shared Postgres
storage, and all nodes serve TLS from that shared store. This removes the current
single-node limitation without requiring an external proxy or externally-provisioned
certs.

## Background / confirmed facts (from code inspection)

- **Current wiring is node-local.** `security/acme/acme.go::New` calls
  `autotls.Load(..., cfg.CacheDir, ...)`, which hardcodes a filesystem cache
  (`dirCache`, `vendor/github.com/mjl-/mox/autotls/autotls.go:161`) and loads/creates
  the ACME account key from a local file (`<acmeDir>/<name>.key`,
  `autotls.go:106-158`). `cmd/octo-mail/main.go:206-228` wires this and logs the
  single-node warning.
- **Three real multi-node hazards** (issue #32, all verified in code):
  1. each node has its own account key file → N accounts;
  2. each node has its own cert cache → N independent orders for the same hosts (LE
     rate limits);
  3. **tls-alpn-01 challenge token certs are held in an in-memory map** — `certTokens`
     (`vendor/github.com/mjl-/autocert/autocert.go:226`, served from `GetCertificate`
     at `:305-316`), NOT in the `Cache`. So a challenge that lands on a node that did
     not create the order cannot be answered. **A shared cache alone cannot fix this**
     (confirms issue's "option A necessary but not sufficient").
- **DNS-01 is not available** in the vendored `mjl-/autocert` — it offers only
  tls-alpn-01 and http-01 (`autocert.go:116-117,414`; `supportedChallengeTypes`).
  But `golang.org/x/crypto/acme` (direct `go.mod` dep, vendored) has the full RFC 8555
  DNS-01 primitives (`Register`/`AuthorizeOrder`/`DNS01ChallengeRecord`/`Accept`/
  `WaitAuthorization`/`CreateOrderCert`). **Decision (see `design.md`): drive the order
  flow directly over `x/crypto/acme` with DNS-01** — the routing-free HA pattern — and
  stop using autocert for cluster issuance/serving.
- No `miekg/dns` is vendored, so RFC2136 programmatic UPDATE is not cheap; the
  production DNS solver is **webhook-based** (matches the existing HMAC webhook in
  `mailflow/deliverability/ob_webhookworker.go`).
- **`autocert.Cache` is a small 3-method interface** (`Get`/`Put`/`Delete`,
  `vendor/github.com/mjl-/autocert/cache.go:22`); `Get` returns
  `autocert.ErrCacheMiss` on no-rows. A pgxpool-backed implementation is
  straightforward.
- **Leader primitive already exists and is battle-tested.** `ops/ha.Coordinator`
  runs registered singleton work only while leader, with crash + promotion failover
  (`ops/ha/{ha,coordinator}.go`). `cmd/octo-mail/main.go:557-561` already defines
  distinct leader keys 1–4 (proj/warmup/reput/report); a new key 5 fits the pattern.
- **Schema precedents**: `bytea` secret storage (`dkim_keys.private_key`,
  `schema/05_deliverability.sql:39`) and name-keyed singleton tables
  (`maintenance_marker`, `schema/05:187`; `leader_lease`, `schema/08`). New DDL is
  idempotent and added as the next numbered file `schema/10_acme_cache.sql`.
- **Test harness**: `security/acme/live_test.go` (`TestACMELiveIssuance`, gated by
  `OCTO_MAIL_ACME=1`, pebble via `scripts/acme-pebble.sh`) drives a real CA over
  tls-alpn-01; `acme_test.go::TestACMEManagerWiring` is the offline construction test.
  Storage tests use real Postgres at `testDSN` with `t.Skip` when absent, `-p 1`.

## Requirements

- **R1 — Postgres-backed `autocert.Cache`.** New table
  `acme_cache(name text PRIMARY KEY, data bytea NOT NULL, updated_at timestamptz NOT
  NULL DEFAULT now())` in `storage/postgres/schema/10_acme_cache.sql` (idempotent
  DDL). A pgxpool-backed type implementing `autocert.Cache`: `Get`→SELECT (no-rows →
  `autocert.ErrCacheMiss`), `Put`→upsert, `Delete`→delete.
- **R2 — Shared ACME account key.** The account key is shared across nodes (stored in
  the shared cache), not read from a per-node file, so the cluster registers ONE ACME
  account. The `x/crypto/acme` client is constructed with the shared-loaded key.
- **R3 — Leader-only issuance.** Only the leader runs the DNS-01 order/renewal pass
  and writes certs into the shared cache, gated by a new `ops/ha.Coordinator` leader
  key (5). Same pattern as the existing leader singletons in `main.go`.
- **R4 — Followers serve-only.** All nodes serve certs read from the shared cache via a
  `GetCertificate` that never issues; leadership is not consulted on the TLS hot path,
  only on the background renewal loop. A per-node refresher picks up leader-renewed
  certs within bounded staleness (~30s).
- **R5 — DNS-01 challenge, routing-free.** Issuance uses the dns-01 challenge: the
  leader publishes `_acme-challenge.<host> TXT` via a pluggable `DNSSolver`
  (webhook-backed in production; challtestsrv in the live test). No inbound challenge
  routing — any node can serve TLS regardless of which node the LB picks. This fully
  closes issue #32 point 3.
- **R6 — Backward compatible.** With no DNS webhook configured, the existing single-node
  tls-alpn-01 path (`acme.New`/autotls) is used unchanged, warning intact. Multi-node
  DNS-01 activates only when `OCTO_MAIL_ACME_DNS_WEBHOOK_URL` is set.
- **R7 — Dependency direction preserved.** `security/acme` takes `*pgxpool.Pool`
  directly (junkfilter precedent); schema DDL stays centralized in
  `storage/postgres/schema`. No `protocol/*` involvement. Vendored `x/crypto/acme` is
  used as-is (reuse boundary); vendored `mjl-/autocert` is NOT patched.

## Acceptance Criteria

- [ ] AC1 (executable): `make vet` and `make fmt` clean; `make build` succeeds.
- [ ] AC2 (executable): new storage test for the pg `autocert.Cache` round-trips
      Get/Put/Delete and maps no-rows to `autocert.ErrCacheMiss`, passing under
      `go test -p 1 ./storage/...` against real Postgres (skips cleanly without DB).
- [ ] AC3 (executable): `schema/10_acme_cache.sql` applies idempotently — `Open`
      twice (fresh + existing) does not error (covered by existing store bootstrap
      in tests).
- [ ] AC4: leader-gated wiring in `cmd/octo-mail/main.go` — a new coordinator (key 5)
      is the only path that runs the DNS-01 renewal pass; all nodes serve read-only from
      the shared cache. Covered by a unit/integration test asserting the serving
      `GetCertificate` never invokes the ACME client/DNS solver (issuance only via
      `RenewOnce`).
- [ ] AC5: the "single-node only" warning + doc comments in `security/acme/acme.go`
      and `main.go` are updated to describe the leader-gated DNS-01 multi-node mode and
      when the legacy single-node path applies.
- [ ] AC6: `docs/architecture.md` / README ACME notes updated to reflect multi-node
      DNS-01 support; issue #32 referenced in the PR.
- [ ] AC7 (best-effort, gated): `TestACMEClusterDNSIssuance` issues against pebble via
      the challtestsrv DNS solver with the Postgres cache backing the manager
      (`OCTO_MAIL_ACME=1`).

## Out of scope

- Cloud DNS-provider plugins (Route53/Cloudflare) and RFC2136 — the webhook solver is
  the provider-neutral seam; concrete providers are follow-ups.
- http-01 / tls-alpn-01 cluster support (DNS-01 is the chosen challenge type).
- Multi-tenant per-domain ACME (issuance is for the node/cluster hostnames only, as
  today).
- Removing the legacy single-node tls-alpn-01 path (kept for backward compatibility).

## Technical notes

Architecture and execution are detailed in `design.md` (DNS-01 decision record,
components, data model, issuance/serving flows, solver seam, mode selection) and
`implement.md` (ordered checklist + validation commands). No blocking open questions
remain.
