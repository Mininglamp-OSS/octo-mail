# Design — Leader-gated cluster ACME issuance (DNS-01)

Implements issue #32 / requirement set in `prd.md`. Chosen architecture:
**DNS-01, leader-gated, shared Postgres storage** (the routing-free HA pattern).

## Why DNS-01 (decision record)

- tls-alpn-01 / http-01 require the CA's inbound validation probe to reach the exact
  node holding an ephemeral challenge secret. In a stateless cluster behind one
  VIP/anycast IP the probe lands on an arbitrary node → race. Confirmed: the token
  cert lives in an unexported in-memory `certTokens` map in vendored
  `mjl-/autocert` (`autocert.go:226`, no hook), so it cannot be shared via the
  `Cache` seam.
- DNS-01 removes inbound routing entirely: the solver publishes
  `_acme-challenge.<host> TXT`, the CA validates via DNS, independent of which node
  runs the solver. This is the cert-manager / CertMagic recommendation for
  multi-replica issuance.
- Vendored `mjl-/autocert` cannot do DNS-01, but `golang.org/x/crypto/acme` (direct
  `go.mod` dep, fully vendored) provides the RFC 8555 primitives
  (`Register`/`AuthorizeOrder`/`DNS01ChallengeRecord`/`Accept`/`WaitAuthorization`/
  `CreateOrderCert`/`WaitOrder`). We drive the order flow directly.

## Components & boundaries

New/changed, all under existing dependency rules (cross-cutting `security/*` may take
`*pgxpool.Pool` directly — precedent: `junkfilter.NewManager(s.Pool, …)`,
`inbound.Decider{Pool: …}`; schema stays centralized in `storage/postgres`).

```
security/acme/
  acme.go        (unchanged) legacy single-node autotls / tls-alpn-01 manager
  cluster.go     NEW  ClusterManager: DNS-01 issuance (leader) + serving (all nodes)
  pgcache.go     NEW  pgCache: *pgxpool.Pool-backed cert/account-key store (autocert.Cache-shaped Get/Put/Delete)
  dnssolver.go   NEW  DNSSolver interface + webhookSolver (prod) + challtestsrvSolver (test)
  cluster_test.go / pgcache_test.go  NEW  real-PG + offline unit tests
  live_test.go   EXTEND  DNS-01 path against pebble + challtestsrv (OCTO_MAIL_ACME=1)

storage/postgres/schema/10_acme_cache.sql  NEW  idempotent DDL

cmd/octo-mail/
  config.go      ADD  OCTO_MAIL_ACME_DNS_WEBHOOK_URL / _SECRET (+ keep existing ACME env)
  main.go        WIRE mode select: DNS webhook set → ClusterManager + coordinator key 5;
                      else → legacy single-node path (unchanged)
```

## Data model

`storage/postgres/schema/10_acme_cache.sql` (mirrors `dkim_keys` bytea +
`maintenance_marker`/`leader_lease` name-keyed singleton precedents):

```sql
CREATE TABLE IF NOT EXISTS acme_cache (
    name       text PRIMARY KEY,          -- storage key (see key scheme below)
    data       bytea NOT NULL,            -- PEM bundle or raw key material
    updated_at timestamptz NOT NULL DEFAULT now()
);
```

Cluster-wide (not account-partitioned): ACME account + certs are node/cluster
identity, not tenant data. Key scheme:

- `acct-key:<sha256(directoryURL)>` → account private key, PKCS#8 PEM.
- `cert:<host>` → concatenated PEM: `PRIVATE KEY` block + `CERTIFICATE` chain
  (leaf first). `tls.X509KeyPair(data, data)` parses it directly.

(The account URL/KID is not persisted: x/crypto/acme re-derives and caches it
in-process from the account key on each leader's first `Register`, which also
returns `ErrAccountAlreadyExists`+KID when the key is already registered.)

`pgCache.Get` maps `pgx.ErrNoRows` → `autocert.ErrCacheMiss` (interface parity even
though we don't use autocert for issuance — keeps the seam standard and testable).

## Issuance flow (leader only)

`ClusterManager.ensureCert(ctx, host)`:

1. **Account**: load `acct-key`; if absent, generate ECDSA P-256, store, then
   `client.Register` (idempotent: x/crypto returns the existing account on conflict);
   persist `acct-url`.
2. `order := client.AuthorizeOrder(ctx, acme.DomainIDs(host))`.
3. For each pending authz: pick the `dns-01` challenge; `rec :=
   client.DNS01ChallengeRecord(chal.Token)`; `solver.Present(ctx,
   "_acme-challenge."+domain, rec)`; `client.Accept(ctx, chal)`;
   `client.WaitAuthorization(ctx, authz.URI)`; `solver.CleanUp(...)` (deferred, always).
4. Generate a fresh per-cert ECDSA P-256 key; build CSR (`DNSNames=[host]`);
   `der := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)`.
5. Encode PEM bundle (key + chain); `pgCache.Put("cert:"+host, bundle)`.

Renewal: the leader coordinator `Tick` iterates `cfg.acmeHosts`; for each, load
`cert:<host>`, parse leaf; if missing or `NotAfter-now < RenewBefore` (30d) → `ensureCert`.
Single-flighted by the coordinator (long Tick never blocks heartbeat). No `FenceExec`
needed: publishing a validly-issued cert is idempotent and harmless under a stale
tenure (worst case a redundant order; leader-gating already bounds concurrency to ~1).

## Serving path (all nodes)

`ClusterManager.TLSConfig()` returns a `*tls.Config` whose `GetCertificate` serves
from an in-memory `map[host]*tls.Certificate`, refreshed from `pgCache`:

- A background goroutine (all nodes) polls `SELECT updated_at FROM acme_cache WHERE
  name='cert:'+host` per managed host every ~30s; reloads+reparses on change. This is
  how a follower picks up a cert the leader just renewed, with bounded staleness.
- `GetCertificate` never issues. On a cold miss it does one synchronous `pgCache.Get`;
  still missing → returns `nil` (TLS "unrecognized name"), exactly like the legacy
  fallback for unknown SNI. Only the leader's renewal loop ever creates certs.

This cleanly satisfies R3 (leader-only issuance) and R4 (followers serve-only) with a
single code path — leadership is not consulted on the hot TLS path at all; it only
gates the background renewal loop.

## DNS solver seam

```go
type DNSSolver interface {
    Present(ctx context.Context, fqdn, value string) error // publish TXT fqdn = value
    CleanUp(ctx context.Context, fqdn, value string) error // remove it
}
```

- **webhookSolver** (production): HTTP POST `{op, fqdn, value}` to
  `OCTO_MAIL_ACME_DNS_WEBHOOK_URL`, HMAC-SHA256 signed with
  `OCTO_MAIL_ACME_DNS_WEBHOOK_SECRET` in an `X-Octo-Signature` header — mirrors the
  existing outbound webhook signing (`mailflow/deliverability/ob_webhookworker.go`,
  `OCTO_MAIL_WEBHOOK_SECRET`). Provider-neutral: operators map their DNS API behind
  the webhook. No new dependency (no `miekg/dns`, so RFC2136 is out).
- **challtestsrvSolver** (test only): POSTs `/set-txt` `/clear-txt` to
  pebble-challtestsrv's mgmt API. Lives behind the `OCTO_MAIL_ACME=1` live test.
- Provider plugins (Route53/Cloudflare/RFC2136) are explicit follow-ups; the webhook
  keeps the core provider-agnostic.

## Config & mode selection (`cmd/octo-mail`)

- New: `OCTO_MAIL_ACME_DNS_WEBHOOK_URL`, `OCTO_MAIL_ACME_DNS_WEBHOOK_SECRET`.
- `main.go` mode select when `cfg.acmeDirectory` && `cfg.acmeContact` set:
  - **DNS webhook configured** → build `ClusterManager` (pgCache on `s.Pool`,
    webhookSolver), register coordinator key 5 whose `Tick` runs the renewal pass,
    start the per-node cert refresher, hand `ClusterManager.TLSConfig()` to
    IMAP/SMTP/HTTPS listeners. Multi-node safe; log it.
  - **no DNS webhook** → legacy `acme.New` (autotls/tls-alpn-01), single-node warning
    unchanged. Preserves R6 backward compatibility for single-node users with no DNS
    provider.
- `OCTO_MAIL_ACME_CACHE` (dir) stays accepted; only the legacy path uses it.

## Compatibility, ops, rollback

- Backward compatible: no config change → identical legacy behavior. Rollback =
  unset the DNS webhook env (falls back to legacy) or revert the commit; the new table
  is additive and unused by the legacy path.
- Leader key 5 joins keys 1–4 in `main.go`; same `lockClassLeader` two-key space, no
  aliasing with per-account (one-key) locks.
- Pool sizing: the cert-refresher uses short pooled queries (not a held connection),
  so unlike a coordinator it adds no permanent pool floor.

## Trade-offs / risks

- Reimplementing the ACME order flow (vs. autocert) is the cost of DNS-01; bounded to
  ~one file (`cluster.go`) using vendored `x/crypto/acme` primitives.
- Live end-to-end issuance remains gated (`OCTO_MAIL_ACME=1`, pebble) — same honest
  boundary as today's `TestACMELiveIssuance`. Non-gated tests cover pgCache, PEM
  round-trip, serving GetCertificate, and webhook solver signing.
- The webhook solver puts DNS mutation behind an operator endpoint; documented as the
  integration contract. Not shipping cloud-provider plugins in this PR.
