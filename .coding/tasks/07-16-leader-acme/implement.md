# Implement — Leader-gated cluster ACME issuance (DNS-01)

Execution plan for `design.md`. Ordered so each step compiles and is independently
checkable. Validation after each block: `make fmt && make vet && make build`.

## Ordered checklist

### 1. Schema (storage substrate)
- [ ] Add `storage/postgres/schema/10_acme_cache.sql` — idempotent
      `CREATE TABLE IF NOT EXISTS acme_cache(name text PRIMARY KEY, data bytea NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now())`. Header comment references the
      `dkim_keys`/`maintenance_marker` precedents.
- [ ] Confirm it is picked up by the `go:embed schema/*.sql` in `storage/postgres/store.go`
      (no code change; verify by grepping the embed + a fresh `Open` in a test).
- Validate: `go test -p 1 ./storage/postgres/ -run TestStore` (or existing bootstrap test) with DB up.

### 2. pgCache (`security/acme/pgcache.go`)
- [ ] `type pgCache struct { pool *pgxpool.Pool }` with `Get/Put/Delete(ctx, name)` —
      `Get` maps `pgx.ErrNoRows` → `autocert.ErrCacheMiss`; `Put` upserts
      (`INSERT … ON CONFLICT (name) DO UPDATE SET data=…, updated_at=now()`); `Delete`
      deletes. Add `updatedAt(ctx, name)` helper for the refresher.
- [ ] `pgcache_test.go`: real-PG round-trip Get/Put/Delete + ErrCacheMiss on miss;
      `t.Skipf` when DB absent; uses `testDSN`. Mirror `junkfilter_test.go` pool setup.
- Validate: `go test -p 1 ./security/acme/ -run TestPGCache`.

### 3. DNS solver (`security/acme/dnssolver.go`)
- [ ] `DNSSolver` interface (`Present`/`CleanUp`).
- [ ] `webhookSolver{url, secret, hc *http.Client}` — POST JSON `{op,fqdn,value}`,
      HMAC-SHA256 header `X-Octo-Signature` (reuse the signing shape from
      `mailflow/deliverability/ob_webhookworker.go`). Non-2xx → error.
- [ ] `dnssolver_test.go`: offline `httptest.Server` asserts payload + signature for
      Present/CleanUp. No DB, no network.
- Validate: `go test ./security/acme/ -run TestWebhookSolver`.

### 4. ClusterManager (`security/acme/cluster.go`) — the core
- [ ] `type ClusterManager` holding `client *acme.Client` (x/crypto), `cache *pgCache`,
      `solver DNSSolver`, `hosts []dns.Domain`, `contact string`, `renewBefore time.Duration`,
      in-mem `certs map[string]*tls.Certificate` + `sync.RWMutex`, `log *slog.Logger`.
- [ ] `NewCluster(cfg)` — construct; do NOT register account eagerly (leader does it).
- [ ] account helpers: `loadOrCreateAccountKey(ctx)`, `ensureRegistered(ctx)`.
- [ ] `ensureCert(ctx, host)` — full DNS-01 order flow (design §Issuance). `defer`
      solver CleanUp. Store PEM bundle via cache.Put.
- [ ] `RenewOnce(ctx)` — iterate hosts, parse stored leaf, renew if missing/near expiry.
      This is the leader `Tick` body.
- [ ] serving: `TLSConfig() *tls.Config` with `GetCertificate` reading `certs` map
      (sync cache.Get on cold miss; never issues). `refreshLoop(ctx)` polls `updated_at`
      per host every ~30s and reloads changed certs. `loadCert(ctx, host)` parses bundle.
- [ ] `SetACMEHTTPClient(hc)` for the pebble live test (trust pebble CA).
- [ ] `cluster_test.go` (real-PG, offline CA): put a self-signed cert bundle in the
      cache → `GetCertificate` serves it; assert a non-leader/serving manager never
      calls the solver/client (issuance only via `RenewOnce`). Use a fake `DNSSolver`
      recorder + a self-signed cert to avoid needing a CA.
- Validate: `go test -p 1 ./security/acme/`.

### 5. Config (`cmd/octo-mail/config.go`)
- [ ] Add `acmeDNSWebhookURL string`, `acmeDNSWebhookSecret []byte` to `config` +
      `loadConfig` (`OCTO_MAIL_ACME_DNS_WEBHOOK_URL`, `_SECRET`). Keep existing ACME vars.
- [ ] `config_test.go`: assert the new vars load (extend existing env test).

### 6. Wiring (`cmd/octo-mail/main.go`)
- [ ] In the ACME block (~L206): if `acmeDNSWebhookURL != ""` → build `ClusterManager`,
      set `acmeTLS = cm.TLSConfig()`, `go cm.refreshLoop(ctx)`, register
      `ha.NewCoordinator(ha.New(s.Pool, acmeLeaderKey, cfg.nodeID), renewInterval)` with
      `Tick = func(ctx){ cm.RenewOnce(ctx) }` and an `OnElected` log; add
      `acmeLeaderKey = int64(5)` to the leader-key block (~L557). Log "multi-node
      DNS-01 ACME (leader-gated)".
    - else → existing legacy path unchanged (keep single-node warning).
- Validate: `make build`.

### 7. Live test (`security/acme/live_test.go`) + script
- [ ] Add `challtestsrvSolver` (test file) posting `/set-txt` `/clear-txt`.
- [ ] Add `TestACMEClusterDNSIssuance` (gated `OCTO_MAIL_ACME=1`, needs DB + pebble):
      build `ClusterManager` with challtestsrv solver + pg cache, `RenewOnce`, assert a
      `cert:<host>` bundle is stored and parses. Extend `scripts/acme-pebble.sh` notes
      for the DNS-01 path (challtestsrv already runs the DNS server).
- Validate (manual, gated): `scripts/acme-pebble.sh up` then `OCTO_MAIL_ACME=1 … go test -run TestACMEClusterDNS ./security/acme/`.

### 8. Docs
- [ ] Update `security/acme/acme.go` package doc + `main.go` warning: describe the new
      leader-gated DNS-01 multi-node mode and when the legacy single-node path applies.
- [ ] Update `docs/architecture.md` (security/acme line) + README ACME note. Reference #32.

## Validation commands (full)
```sh
make fmt && make vet && make build
make test        # go test -p 1 ./...  (real Postgres + MinIO; skips w/o infra)
# gated live issuance (manual):
scripts/acme-pebble.sh up
OCTO_MAIL_ACME=1 OCTO_MAIL_ACME_CA=/tmp/octo-mail-pebble-minica.pem go test -run TestACMEClusterDNS ./security/acme/
```

## Risky files / rollback points
- `cmd/octo-mail/main.go` — wiring is the integration risk; the `if webhook` guard
  isolates new behavior. Rollback = unset `OCTO_MAIL_ACME_DNS_WEBHOOK_URL`.
- `security/acme/cluster.go` — the only place implementing the ACME order flow; keep
  it self-contained and covered by the offline serving test + gated live test.
- Schema `10_acme_cache.sql` is additive/idempotent; safe to leave even on rollback.

## Pre-start follow-ups
- Curate `implement.jsonl` / `check.jsonl` with the spec files below (done in planning).
- Review gate: user approves `prd.md` + `design.md` + `implement.md` before `task.py start`.
