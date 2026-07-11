// Command octo-mail runs a single stateless octo-mail node: it opens the shared Postgres
// + blob store, starts the cross-node coordinator, and serves every front door
// (SMTP receive on :25, SMTP submission on :587, IMAP on :143, JMAP over HTTP),
// plus the background workers (outbound queue delivery, async FTS/threading
// projections). Any number of these processes run against the same PG+S3 — no
// node owns an account or the queue; that is the whole architecture, booted.
//
// Configuration is via environment variables (12-factor); see envDefault calls.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/junkfilter"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreply"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/ops/ha"
	"github.com/Mininglamp-OSS/octo-mail/ops/obs"
	"github.com/Mininglamp-OSS/octo-mail/ops/reportdb"
	"github.com/Mininglamp-OSS/octo-mail/ops/webadmin"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/acme"
	"github.com/Mininglamp-OSS/octo-mail/security/privsep"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/Mininglamp-OSS/octo-mail/webui"
	"github.com/mjl-/autocert"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

func main() {
	// Subcommands for provisioning/ops; default (no subcommand) runs the server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			// explicit server run
		case "passwd":
			if err := cmdPasswd(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "octo-mail passwd:", err)
				os.Exit(1)
			}
			return
		case "gendkim":
			if err := cmdGenDKIM(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "octo-mail gendkim:", err)
				os.Exit(1)
			}
			return
		case "apikey":
			if err := cmdAPIKey(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "octo-mail apikey:", err)
				os.Exit(1)
			}
			return
		case "export":
			if err := cmdExport(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "octo-mail export:", err)
				os.Exit(1)
			}
			return
		case "import":
			if err := cmdImport(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "octo-mail import:", err)
				os.Exit(1)
			}
			return
		default:
			fmt.Fprintf(os.Stderr, "octo-mail: unknown subcommand %q (use: serve | passwd | gendkim | apikey | export | import)\n", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "octo-mail:", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := loadConfig()
	// Validate VERP config once, up front, before ANY VERP wiring (inbound MX or
	// outbound signer). Gating this inside the MX block would let a submission-/
	// outbound-only node (smtpAddr="") enable a bounce domain without a key and
	// silently emit unsigned, forgeable return-paths — the exact fail-open the
	// control exists to prevent.
	if err := checkVERPConfig(cfg); err != nil {
		return err
	}
	if err := checkReporterConfig(cfg); err != nil {
		return err
	}
	if err := validate(cfg, log); err != nil {
		return err
	}
	if cfg.bounceDomain != "" && len(cfg.verpKey) == 0 {
		// Reached only with the explicit dev escape hatch (else checkVERPConfig is
		// fatal). Warn on every VERP-enabling topology, inbound or outbound-only.
		log.Warn("VERP signing key not set (OCTO_MAIL_VERP_KEY); bounce/complaint attribution is forgeable — dev-only unsigned path enabled via OCTO_MAIL_ALLOW_UNSIGNED_VERP", "bounce_domain", cfg.bounceDomain)
	}
	if os.Getenv("OCTO_MAIL_JUNK_DIR") != "" {
		// Junk-filter state moved from per-node files to shared Postgres
		// (junk_words/junk_totals). The env is no longer consumed; warn rather than
		// silently ignore it so an operator who set it knows their old file-based
		// state is orphaned (there is no automatic migration — accounts retrain).
		log.Warn("OCTO_MAIL_JUNK_DIR is set but ignored: junk-filter state now lives in Postgres (shared across nodes); any old file-based junk state on disk is orphaned and no longer used")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Blob store: S3 if configured, else local filesystem.
	bs, err := openBlobStore(cfg, log)
	if err != nil {
		return err
	}

	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()
	log.Info("store opened; schema applied", "dsn", redactDSN(cfg.dsn))

	if err := s.StartCoordinator(ctx); err != nil {
		return fmt.Errorf("start coordinator: %w", err)
	}
	log.Info("coordinator started (LISTEN/NOTIFY doorbell)")

	dir := s.NewDirectory()
	submitter := &submit.Submitter{Pool: s.Pool, Blob: bs}
	repo := &deliverability.Service{Pool: s.Pool, MaxPerWindow: cfg.sendRateMax, RateWindow: cfg.sendRateWindow}
	signer := &deliverability.DKIMSigner{Pool: s.Pool}
	// Optional DKIM key encryption at rest.
	if secret := os.Getenv("OCTO_MAIL_KEY_SECRET"); secret != "" {
		kc, err := deliverability.NewKeyCipher([]byte(secret))
		if err != nil {
			return fmt.Errorf("key cipher: %w", err)
		}
		signer.Cipher = kc
		log.Info("DKIM key encryption at rest enabled")
	}

	// --- Front doors ---
	errc := make(chan error, 8)
	// drain coordinates graceful shutdown: HTTP servers to Shutdown() and a
	// WaitGroup of in-flight connection handlers + worker-loop iterations awaited on
	// SIGTERM (bounded by cfg.drainTimeout).
	drain := &drainSet{}

	// Privilege separation: when OCTO_MAIL_RUN_AS is set, bind all privileged TCP
	// ports while still root, then irreversibly drop to the unprivileged user
	// before serving any client (the root→unprivileged-user model, done in-process).
	prebound := map[string]net.Listener{}
	if spec := os.Getenv("OCTO_MAIL_RUN_AS"); spec != "" {
		ids, err := privsep.ResolveUser(spec)
		if err != nil {
			return fmt.Errorf("privsep: %w", err)
		}
		// With the fs blob backend, the blob root was just created owned by root,
		// but tenant/shard subdirs are made lazily at write time by the dropped
		// unprivileged process — which can't MkdirAll inside a root-owned tree. Hand
		// the tree to the target user before dropping. (S3 backend has no local dir.)
		if cfg.s3Endpoint == "" {
			if err := privsep.ChownTree(cfg.blobDir, ids); err != nil {
				return fmt.Errorf("privsep: chown blob dir: %w", err)
			}
		}
		addrs := map[string]string{
			"smtp-mx":         cfg.smtpAddr,
			"smtp-submission": cfg.submissionAddr,
			"imap":            cfg.imapAddr,
		}
		// The JMAP/webmail HTTPS listener carries the ACME tls-alpn-01 responder and
		// is typically on the privileged :443, so prebind it too (before dropping
		// root) when ACME is enabled — otherwise the CA's challenge can't reach it.
		if cfg.jmapAddr != "" && cfg.acmeDirectory != "" && cfg.acmeContact != "" {
			addrs["jmap"] = cfg.jmapAddr
		}
		prebound, err = privsep.Sequence(addrs, ids, privsep.DropPrivileges)
		if err != nil {
			return fmt.Errorf("privsep: %w", err)
		}
		log.Info("privilege separation: bound privileged ports, dropped to unprivileged user", "uid", ids.UID, "gid", ids.GID)
	}

	// Optional ACME/autotls: when configured, listeners use automatic certs.
	// In shared mode (default when ACME is enabled) the account key + certs + the
	// tls-alpn-01 challenge tokens live in a shared Postgres cache and issuance is
	// leader-gated, so the stateless cluster runs built-in ACME safely (issue #32).
	// Set OCTO_MAIL_ACME_SHARED=0 for the legacy node-local single-node behavior.
	var acmeMail, acmeHTTPS *tls.Config
	if cfg.acmeDirectory != "" && cfg.acmeContact != "" {
		var acmeCache autocert.Cache
		if cfg.acmeShared {
			acmeCache = postgres.AcmeCache{Pool: s.Pool}
			// Encrypt cert + ACME account private keys at rest with the same cipher as
			// DKIM keys, when a master secret is configured — otherwise an operator who
			// set OCTO_MAIL_KEY_SECRET (expecting all private keys at rest encrypted)
			// would have plaintext TLS/account keys in a DB dump. Unset secret =
			// plaintext, matching the DKIM path (operator's explicit choice).
			if signer.Cipher != nil {
				acmeCache = deliverability.EncryptingCache{Inner: acmeCache, Cipher: signer.Cipher}
				log.Info("ACME cert/account key encryption at rest enabled")
			}
		}
		// Effective issuance host set: the configured ACME hosts plus this node's
		// real hostname (which is also the SNI fallback, so it must have a cert). In
		// shared mode the leader Tick is the ONLY issuance path (the serving path
		// never orders), so an empty set means no cert is ever issued — validate()
		// refuses that config, but guard here too and always include a real hostname.
		acmeIssueHosts := append([]dns.Domain(nil), cfg.acmeHosts...)
		if cfg.hostname != "" && cfg.hostname != "octo-mail.local" {
			h := dns.Domain{ASCII: cfg.hostname}
			seen := false
			for _, x := range acmeIssueHosts {
				if x.ASCII == h.ASCII {
					seen = true
					break
				}
			}
			if !seen {
				acmeIssueHosts = append(acmeIssueHosts, h)
			}
		}
		am, err := acme.New(acme.Config{
			CacheDir:     cfg.acmeCacheDir,
			ContactEmail: cfg.acmeContact,
			DirectoryURL: cfg.acmeDirectory,
			Hostnames:    acmeIssueHosts,
			Fallback:     dns.Domain{ASCII: cfg.hostname},
			Shutdown:     ctx.Done(),
			Cache:        acmeCache,
		})
		if err != nil {
			return fmt.Errorf("acme: %w", err)
		}
		acmeMail = am.MailTLSConfig()
		acmeHTTPS = am.HTTPSTLSConfig()
		if cfg.acmeShared {
			log.Info("ACME/autotls enabled (shared cache, leader-gated issuance)", "directory", cfg.acmeDirectory, "hosts", acmeIssueHosts)
			// Leader-gated issuance: only the leader orders certs (into the shared
			// cache); followers serve certs — and answer tls-alpn-01 challenges — from
			// the cache and never order. The leader Tick pre-warms/renews each host so
			// issuance happens ahead of client traffic and autocert's renew timers are
			// re-established after a restart. tls-alpn-01 validation lands on :443, so
			// the HTTPS listener must be reachable there (see the JMAP wiring below).
			const acmeLeaderKey = int64(5) // advisory-lock objid within lockClassLeader; must fit int32
			acmeCoord := ha.NewCoordinator(ha.New(s.Pool, acmeLeaderKey, cfg.nodeID), 5*time.Minute)
			acmeCoord.OnElected = func(context.Context) {
				am.SetLeader(true)
				log.Info("elected ACME issuance leader", "node", cfg.nodeID)
			}
			acmeCoord.OnLost = func() {
				am.SetLeader(false)
				log.Info("lost ACME issuance leadership", "node", cfg.nodeID)
			}
			acmeCoord.Tick = func(ctx context.Context) {
				for _, h := range acmeIssueHosts {
					if err := am.EnsureCert(ctx, h); err != nil {
						log.WarnContext(ctx, "ACME pre-warm/renew", "host", h.ASCII, "err", err)
					}
				}
			}
			go acmeCoord.Run(ctx)
		} else {
			log.Info("ACME/autotls enabled", "directory", cfg.acmeDirectory, "hosts", cfg.acmeHosts)
			// Legacy node-local mode (OCTO_MAIL_ACME_SHARED=0): the cache (account key
			// + certs) is a node-local directory, so built-in ACME is single-node only.
			// Running it on multiple nodes makes each register its own account and race
			// to order the same certs, and a tls-alpn-01 challenge can land on a node
			// that didn't create the order. Multi-node deployments must either enable
			// the shared cache (the default) or terminate TLS at a shared proxy.
			log.Warn("built-in ACME is in node-local (single-node) mode; enable the shared cache (unset OCTO_MAIL_ACME_SHARED=0) or terminate TLS at a shared proxy for multi-node")
		}
	}

	// Inbound authenticator (SPF/DKIM/DMARC/iprev/DNSBL) for the MX listener.
	authenticator := &inbound.Authenticator{Resolver: dns.StrictResolver{Pkg: "octo-mail"}, DNSBLZones: cfg.dnsblZones}
	decider := &inbound.Decider{
		Pool:              s.Pool,
		GreylistEnabled:   cfg.greylist,
		GreylistDelay:     cfg.greylistDelay,
		JunkThreshold:     cfg.junkThreshold,
		RejectThreshold:   cfg.rejectThreshold,
		TrustedHamCount:   cfg.trustedHamCount,
		SubjectPassKey:    cfg.subjectPassKey,
		SubjectPassPeriod: cfg.subjectPassPeriod,
	}
	reports := &reportdb.Store{Pool: s.Pool}

	// Surface security-relevant weakened defaults at startup so an operator does
	// not silently run with spoofing enforcement off. These stay opt-in (flipping
	// them on by default could reject legitimate mail from misconfigured senders),
	// but running without them should be a conscious choice, not an accident.
	if !cfg.rejectDMARC {
		log.Warn("DMARC enforcement OFF: messages failing a domain's DMARC p=reject policy are accepted (spoofing risk). Set OCTO_MAIL_REJECT_DMARC=1 to enforce.")
	}
	if len(cfg.subjectPassKey) == 0 {
		log.Info("subjectpass disabled (no OCTO_MAIL_SUBJECTPASS_KEY); content-rejected senders get no challenge-retry path")
	}

	// Per-account junk filter (bayesian), routing spam to the Junk mailbox. State
	// lives in Postgres (shared across nodes), not per-node files.
	junkMgr := junkfilter.NewManager(s.Pool, junkfilter.DefaultParams, cfg.junkThreshold)
	defer junkMgr.Close()

	// SMTP receive (MX, :25).
	if cfg.smtpAddr != "" {
		vacation := &autoreply.Responder{Lookup: s.LookupAccountByID, Submitter: submitter}
		mx := &smtpd.Server{Dir: dir, Hostname: cfg.hostname, MaxSize: cfg.maxSize, TLSConfig: nil, Auth: authenticator, RejectDMARCFail: cfg.rejectDMARC, MaxHops: cfg.maxHops, Junk: junkMgr, Decider: decider,
			DMARCRecorder: func(ctx context.Context, fromDomain, rua, sourceIP, spf, dkim, disposition string) {
				_ = reports.RecordDMARCAgg(ctx, fromDomain, rua, sourceIP, spf, dkim, disposition)
			},
			VacationResponder: func(ctx context.Context, accountID int64, sender, recipient string, raw []byte) {
				if err := vacation.Respond(ctx, accountID, sender, recipient, raw); err != nil {
					log.WarnContext(ctx, "vacation auto-reply failed", "err", err)
				}
			},
		}
		// VERP inbound: route bounce-domain mail (ARF complaints + DSN bounces) to
		// reputation + suppression, attributed to the sending tenant via the VERP
		// token. Enabled only when a bounce domain is configured.
		if cfg.bounceDomain != "" {
			mx.BounceDomain = cfg.bounceDomain
			mx.BounceHandler = func(ctx context.Context, verpLocalpart string, raw []byte) {
				c, ok, err := repo.IngestReport(ctx, verpLocalpart, cfg.verpKey, raw)
				if err != nil {
					log.WarnContext(ctx, "bounce ingest", "err", err)
					return
				}
				if !ok {
					// Forged/unauthenticated VERP recipient — attribute nothing.
					log.WarnContext(ctx, "unauthenticated bounce/complaint to bounce domain", "verp", verpLocalpart)
					return
				}
				// Attribution is authenticated (signed VERP token), so the tenant
				// reputation event is trustworthy. We deliberately do NOT
				// auto-suppress here: an ARF report only identifies the recipient
				// DOMAIN, and honoring a domain-level suppression from a report would
				// let one complaint silence a tenant's mail to a whole provider.
				// Suppression stays driven by the delivery-time hard-bounce path.
				log.InfoContext(ctx, "bounce/complaint recorded", "tenant", c.TenantID, "kind", c.Kind)
			}
		}
		// Report ingestion: route mail addressed to the report domain (DMARC RUA /
		// TLS-RPT) to the report store instead of a mailbox. Enabled with the reporter
		// role + a configured report domain.
		if cfg.reporter && cfg.reportDomain != "" {
			mx.ReportDomain = cfg.reportDomain
			mx.ReportHandler = func(ctx context.Context, localpart string, raw []byte) {
				kind, err := reports.IngestMessage(ctx, raw, s.DomainOwned)
				if err != nil {
					log.WarnContext(ctx, "report ingest", "localpart", localpart, "err", err)
					return
				}
				log.InfoContext(ctx, "report ingested", "kind", kind, "localpart", localpart)
			}
		}
		go serveTCPListener(ctx, log, "smtp-mx", cfg.smtpAddr, prebound["smtp-mx"], errc, cfg.maxConns, drain, func(nc net.Conn) { _ = mx.Serve(ctx, nc) })
	}
	// SMTP submission (:587).
	if cfg.submissionAddr != "" {
		sub := &smtpd.Server{Dir: dir, Hostname: cfg.hostname, MaxSize: cfg.maxSize, Submission: submitter, TLSConfig: acmeMail}
		// BURL (RFC 4468): resolve an authorized IMAP URL to message bytes within
		// the submitting account, reusing the IMAP URLAUTH validator.
		sub.BURLResolver = func(ctx context.Context, accountID int64, authURL string) ([]byte, bool) {
			acc, _, _, err := s.LookupAccountByID(ctx, accountID)
			if err != nil {
				return nil, false
			}
			return imapd.ResolveURLAuth(ctx, acc, authURL)
		}
		go serveTCPListener(ctx, log, "smtp-submission", cfg.submissionAddr, prebound["smtp-submission"], errc, cfg.maxConns, drain, func(nc net.Conn) { _ = sub.Serve(ctx, nc) })
	}
	// Shared per-IP login throttle for the network auth surfaces (IMAP + JMAP +
	// REST). Bounds brute-force / credential-stuffing and login/API-key
	// enumeration: at most a few failed attempts per client IP per minute.
	loginLimiter := &ratelimit.Limiter{WindowLimits: []ratelimit.WindowLimit{{
		Window: time.Minute,
		Limits: [3]int64{10, 100, 1000}, // per /32, /64-ish, /48-ish IP class
	}}}

	// IMAP (:143).
	if cfg.imapAddr != "" {
		imap := &imapd.Server{Dir: dir, Junk: junkMgr, TLSConfig: acmeMail, MaxSize: cfg.maxSize, LoginLimiter: loginLimiter}
		go serveTCPListener(ctx, log, "imap", cfg.imapAddr, prebound["imap"], errc, cfg.maxConns, drain, func(nc net.Conn) { _ = imap.Serve(ctx, nc) })
	}
	// JMAP (HTTP) + webmail SPA (same origin, so the SPA's /jmap/* fetches work).
	if cfg.jmapAddr != "" {
		js := &jmapd.Server{Dir: dir, BaseURL: cfg.jmapBaseURL, Submission: submitter, Blob: bs, Log: log, LoginLimiter: loginLimiter}
		wa := &webapi.Server{Dir: dir, Submission: submitter, Suppressions: &deliverability.Suppressions{Pool: s.Pool}, Log: log, LoginLimiter: loginLimiter}
		mux := http.NewServeMux()
		mux.Handle("/jmap/", js.Handler())
		mux.Handle("/webapi/", wa.Handler())
		mux.Handle("/webmail", webui.Handler())
		mux.Handle("/webmail/", webui.Handler())
		// With ACME enabled the HTTPS config carries the tls-alpn-01 responder, so
		// this listener (on :443) both serves web traffic and answers ACME challenges.
		srv := &http.Server{Addr: cfg.jmapAddr, Handler: mux, TLSConfig: acmeHTTPS}
		go serveHTTP(log, "jmap+webmail", srv, cfg.maxConns, drain, prebound["jmap"], errc)
	}
	// Admin/account API + healthz (HTTP).
	if cfg.adminAddr != "" {
		// Operators failing a queued message from the admin API bounce it back to
		// the sender via the same DSN generator the worker uses at max attempts.
		failDSN := &submit.DSNGenerator{Opener: s, Hostname: dns.Domain{ASCII: cfg.hostname}, Blob: bs}
		as := &webadmin.Server{Pool: s.Pool, Dir: dir, Reputation: repo, AdminToken: cfg.adminToken, Log: log,
			QueueFailDSN: failDSN.Generate}
		srv := &http.Server{Addr: cfg.adminAddr, Handler: as.Handler()}
		go serveHTTP(log, "admin", srv, cfg.maxConns, drain, nil, errc)
	}

	// --- Background workers ---
	// Outbound send-hardening: suppression list, webhook events, MTA-STS TLS.
	suppress := &deliverability.Suppressions{Pool: s.Pool}
	webhooks := &deliverability.Webhooks{Pool: s.Pool}
	tlsPolicy := &deliverability.TLSPolicy{Resolver: dns.StrictResolver{Pkg: "octo-mail"}}

	// Outbound queue delivery. When an egress IP pool is configured, deliveries
	// bind a per-tenant source IP leased from the IPRouter (warmup/reputation
	// isolation reaches the socket); otherwise the OS default source is used
	// (pickSource nil).
	var pickSource func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error)
	if cfg.egressPool {
		ipr := &deliverability.IPRouter{Pool: s.Pool}
		pickSource = func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error) {
			tid := submit.TenantFrom(ctx)
			if tid == 0 {
				return nil, nil // no tenant → OS default source
			}
			leased, err := ipr.LeaseSourceIP(ctx, tid)
			if err != nil {
				return nil, err // ErrNoSourceIP defers the send (no unwarmed/foreign IP)
			}
			return leased.IP, nil
		}
	}
	dial := submit.SourceIPDialer(resolveMX, pickSource)
	deliverer := &submit.SMTPDeliverer{
		Blob:         bs,
		Dial:         dial,
		EHLOHostname: dns.Domain{ASCII: cfg.hostname},
		TLSMode:      smtpclient.TLSOpportunistic,
		Log:          log,
		Gate: func(ctx context.Context, tid int64, dom string) error {
			r, e := repo.Gate(ctx, tid, dom)
			if e != nil {
				return e
			}
			if !r.Allowed {
				return fmt.Errorf("tenant paused for %s: %s", dom, r.Reason)
			}
			// Per-tenant outbound rate limit (independent of the egress pool). Over
			// the cap returns an error so the queue defers and retries later — not a
			// hard bounce; the tenant is sending, just too fast for this window.
			ok, e := repo.AllowSend(ctx, tid)
			if e != nil {
				return e
			}
			if !ok {
				return fmt.Errorf("tenant %d over send-rate limit; deferring", tid)
			}
			return nil
		},
		Sign:       signer.Sign,
		RecordSent: repo.RecordSent,
		Suppressed: suppress.Suppressed,
		TLSModeFor: func(ctx context.Context, domain string) (smtpclient.TLSMode, error) {
			mode, _, err := tlsPolicy.ModeFor(ctx, domain)
			return mode, err
		},
		// DANE (RFC 7672): when the MX host publishes DNSSEC-authenticated TLSA
		// records, require STARTTLS and verify the peer against them. Gated on the
		// adns authentic bit — no downgrade to unauthenticated TLSA data.
		DANEFor: deliverability.Lookup(dns.StrictResolver{Pkg: "octo-mail"}),
		OnDelivered: func(ctx context.Context, m queue.Msg) {
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "delivered",
				map[string]any{"rcpt": m.RcptTo, "msgid": m.ID})
		},
		OnSendError: func(ctx context.Context, m queue.Msg, err error) {
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "error",
				map[string]any{"rcpt": m.RcptTo, "error": err.Error()})
		},
	}
	// VERP: when a bounce domain is configured, rewrite the envelope MAIL FROM to
	// a per-message VERP token so bounces + FBL complaints attribute to the exact
	// sending tenant. The visible From + DKIM are unchanged (DMARC stays aligned
	// via the tenant's own domain).
	if cfg.bounceDomain != "" {
		deliverer.EnvelopeFrom = func(m queue.Msg) string {
			// Preserve the null sender (a bounce/notification has MAIL FROM:<>);
			// only rewrite a real sender to the signed VERP return-path.
			if m.MailFrom == "" {
				return ""
			}
			return deliverability.SignedVERPToken(m.TenantID, m.ID, cfg.verpKey) + "@" + cfg.bounceDomain
		}
	}
	worker := &queue.Worker{Pool: s.Pool, NodeID: cfg.nodeID, Deliver: deliverer.Deliver, Batch: 20,
		Backoff: cfg.queueBackoff, MaxBackoff: cfg.queueMaxBackoff, MaxLifetime: cfg.queueMaxLifetime,
		DelayThreshold: cfg.queueDelayDSN, RetiredKeep: cfg.queueRetKeep,
		ObserveDelivery: func(d time.Duration, result string) {
			obs.QueueDeliveryDuration.WithLabelValues(result).Observe(d.Seconds())
		},
		OnDelayed: func(ctx context.Context, m queue.Msg) error {
			// Retried enough times to warrant telling the sender we're still trying.
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "delayed",
				map[string]any{"rcpt": m.RcptTo, "msgid": m.ID, "attempts": m.Attempts})
			return nil
		},
		OnFailed: func(ctx context.Context, m queue.Msg, cause error) error {
			dom := ""
			if at := strings.LastIndexByte(m.RcptTo, '@'); at >= 0 {
				dom = m.RcptTo[at+1:]
			}
			// Distinguish a genuine hard bounce (permanent 5xx) from transient
			// exhaustion (the destination kept deferring until the retry lifetime /
			// attempt budget ran out, or we never got an SMTP code at all — e.g. a
			// connection error). Only a real 5xx should suppress the recipient and
			// count as a reputation bounce; suppressing on transient exhaustion would
			// wrongly blacklist a recipient whose server was merely down.
			var perm queue.PermanentError
			permanent := errors.As(cause, &perm) && perm.Permanent()
			if permanent {
				if err := suppress.Add(ctx, m.TenantID, m.AccountID, m.RcptTo, "hard bounce (5xx)"); err != nil {
					log.Warn("suppress on bounce", "err", err)
				}
				if dom != "" {
					// Delivery-time hard bounce: no single signed msgID to dedup on, so
					// pass 0 (non-idempotent — these are our own authenticated events).
					_ = repo.RecordEvent(ctx, m.TenantID, m.AccountID, deliverability.KindBounce, dom, 0)
				}
				_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "bounced",
					map[string]any{"rcpt": m.RcptTo, "msgid": m.ID})
				return nil
			}
			// Transient exhaustion: record a deferral (feeds the windowed reputation
			// view without moving the pause needle) and DO NOT suppress. Still emit a
			// webhook so the sender learns delivery was abandoned, tagged as such.
			if dom != "" {
				_ = repo.RecordEvent(ctx, m.TenantID, m.AccountID, deliverability.KindDeferral, dom, 0)
			}
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "failed",
				map[string]any{"rcpt": m.RcptTo, "msgid": m.ID, "reason": "retry lifetime exhausted"})
			return nil
		},
	}
	drain.goLoop(ctx, log, "queue-worker", cfg.queueInterval, func() {
		if n, err := worker.RunOnce(ctx); err != nil {
			log.Warn("queue worker", "err", err)
		} else if n > 0 {
			log.Info("queue worker delivered", "count", n)
		}
	})

	// Retired-message retention sweep: drop retired queue rows (and their results)
	// past keep_until. Safe on every node (a plain DELETE by time); hourly is fine.
	drain.goLoop(ctx, log, "queue-cleanup", time.Hour, func() {
		if n, err := queue.CleanupRetired(ctx, s.Pool); err != nil {
			log.Warn("queue retired cleanup", "err", err)
		} else if n > 0 {
			log.Info("queue retired cleaned", "count", n)
		}
	})

	// Blob GC: hard-delete expunged message rows (their history lives in the
	// changelog) and reclaim any body blob no live message/queue row references.
	// Without this, storage grows monotonically — every expunge leaks its body.
	// Safe on every node: the row delete uses FOR UPDATE SKIP LOCKED and the
	// per-blob referrer re-check is authoritative at delete time.
	drain.goLoop(ctx, log, "blob-gc", time.Hour, func() {
		rows, blobs, err := s.CollectGarbage(ctx, 1000)
		if err != nil {
			log.Warn("blob gc", "err", err)
		} else if rows > 0 || blobs > 0 {
			log.Info("blob gc", "rows_deleted", rows, "blobs_removed", blobs)
		}
	})

	// Queue depth gauge sampler: publish due/held/total to Prometheus each tick.
	// Safe on every node (a read-only aggregate); the scraper sees the latest value.
	drain.goLoop(ctx, log, "queue-depth", 15*time.Second, func() {
		d, err := queue.Depth(ctx, s.Pool)
		if err != nil {
			log.Warn("queue depth sample", "err", err)
			return
		}
		obs.QueueDepth.WithLabelValues("total").Set(float64(d.Total))
		obs.QueueDepth.WithLabelValues("due").Set(float64(d.Due))
		obs.QueueDepth.WithLabelValues("held").Set(float64(d.Held))
	})

	// Async projection workers (FTS + threading) over all accounts. These run as
	// a cluster singleton: an ha.Coordinator campaigns for leadership and drains
	// projections only on the elected node, with automatic failover if it crashes
	// (a standby is elected and resumes the drains). The queue/webhook workers
	// above are safe on every node (FOR UPDATE SKIP LOCKED leases), so they are
	// not gated.
	fts := &projection.FTSWorker{Pool: s.Pool, Blob: bs, Batch: 100}
	threads := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 100, Log: log}
	// Leader-election objids. Each cluster-singleton subsystem campaigns on a
	// distinct objid within the ha leader lock CLASS (see ops/ha.lockClassLeader);
	// small explicit integers, self-evidently non-colliding. They also serve as the
	// leader_lease.key. The account write-lock keyspace is a SEPARATE (one-arg)
	// advisory-lock space, so these can never alias an account id.
	const (
		projLeaderKey   = int64(1) // projection drain
		warmupLeaderKey = int64(2) // IP warmup daily maintenance
		reputLeaderKey  = int64(3) // reputation auto-unpause
		reportLeaderKey = int64(4) // DMARC/TLS-RPT report scheduler
	)
	projCoord := ha.NewCoordinator(ha.New(s.Pool, projLeaderKey, cfg.nodeID), cfg.projInterval)
	projCoord.OnElected = func(context.Context) { log.Info("elected projection-drain leader", "node", cfg.nodeID) }
	projCoord.OnLost = func() { log.Info("lost projection-drain leadership", "node", cfg.nodeID) }
	projDrainer := &projectionDrainer{s: s, fts: fts, threads: threads, log: log, pageSize: 500}
	projCoord.Tick = projDrainer.tick
	go projCoord.Run(ctx)

	// Daily IP-warmup maintenance, when an egress pool is configured. This MUST be
	// a cluster singleton (it resets/advances shared per-IP counters), so it is
	// leader-gated via its own coordinator — never run per-node. Without it,
	// sent_today never resets and every warming IP wedges at its stage-0 cap,
	// deferring then bouncing all egress-pool deliveries within a day or two.
	if cfg.egressPool {
		ipr := &deliverability.IPRouter{Pool: s.Pool}
		warmCoord := ha.NewCoordinator(ha.New(s.Pool, warmupLeaderKey, cfg.nodeID), time.Hour)
		warmCoord.OnElected = func(context.Context) { log.Info("elected warmup-maintenance leader", "node", cfg.nodeID) }
		warmCoord.OnLost = func() { log.Info("lost warmup-maintenance leadership", "node", cfg.nodeID) }
		warmCoord.Tick = func(ctx context.Context) {
			// RunDailyMaintenance claims the day atomically and no-ops if already
			// done, so this frequent tick (and any post-failover leader) runs the
			// advance+reset exactly once per UTC day.
			if ran, n, err := ipr.RunDailyMaintenance(ctx); err != nil {
				log.Warn("warmup daily maintenance", "err", err)
			} else if ran {
				log.Info("warmup daily maintenance ran", "advanced_ips", n)
			}
		}
		go warmCoord.Run(ctx)
	}

	// Reputation auto-unpause: a cluster singleton that periodically clears the
	// pause flag for (tenant, domain) pairs whose recent windowed bounce/complaint
	// rates have recovered. Leader-gated because it is a shared-state sweep; without
	// it an auto-paused domain stays paused until a manual DB edit (issue #33).
	{
		repuCoord := ha.NewCoordinator(ha.New(s.Pool, reputLeaderKey, cfg.nodeID), 15*time.Minute)
		repuCoord.OnElected = func(context.Context) { log.Info("elected reputation-unpause leader", "node", cfg.nodeID) }
		repuCoord.OnLost = func() { log.Info("lost reputation-unpause leadership", "node", cfg.nodeID) }
		repuCoord.Tick = func(ctx context.Context) {
			if n, err := repo.UnpauseRecovered(ctx); err != nil {
				log.Warn("reputation auto-unpause", "err", err)
			} else if n > 0 {
				log.Info("reputation auto-unpause", "unpaused", n)
			}
			// Prune elapsed per-tenant rate-limit windows here (not in the warmup
			// maintenance leader, which only runs when the egress pool is on) so the
			// table is bounded even in the rate-limiter-without-egress-pool config.
			if n, err := repo.PruneSendRate(ctx); err != nil {
				log.Warn("send-rate prune", "err", err)
			} else if n > 0 {
				log.Info("send-rate prune", "rows", n)
			}
		}
		go repuCoord.Run(ctx)
	}

	// RFC 7489 report role: a leader-gated scheduler that turns accumulated
	// dmarc_agg rows into outbound aggregate reports. Opt-in (sends mail to third
	// parties) and a cluster singleton with a NON-idempotent side effect, so it is
	// leader-gated AND epoch-fenced (C2): across a PG promotion two leaders must not
	// double-send. Reports are submitted as a reserved system tenant/account (the
	// queue's tenant_id/account_id FKs require real rows for node-originated mail).
	if cfg.reporter {
		sysTenantID, sysAccountID, err := s.EnsureSystemAccount(ctx)
		if err != nil {
			return fmt.Errorf("provision system account for reporter: %w", err)
		}
		orgDomain := cfg.hostname
		orgEmail := "dmarc-reports@" + cfg.hostname
		reportResolver := dns.StrictResolver{Pkg: "octo-mail"}
		// RFC 7489 §7.1 anti-reflection: only send an aggregate report to a rua whose
		// domain is authorized to receive reports for the reported domain. A rua in
		// the SAME domain as the reported domain is implicitly authorized (no lookup);
		// a third-party rua must publish "<reported>._report._dmarc.<rua-domain>".
		// Without this, a sender could publish rua=mailto:victim@x and steer us into
		// mailing reports to an arbitrary address. Distinguishes a permanent denial
		// (no opt-in record) from a transient DNS failure so a temperror doesn't
		// permanently drop a legitimate window.
		ruaAuthorized := func(ctx context.Context, reportedDomain, ruaAddr string) reportdb.RUAResult {
			addr, err := smtp.ParseAddress(ruaAddr)
			if err != nil {
				return reportdb.RUADenied // unparseable rua — never send
			}
			ruaDomain := addr.Domain
			rd, err := dns.ParseDomain(reportedDomain)
			if err != nil {
				return reportdb.RUADenied
			}
			if ruaDomain.ASCII == rd.ASCII {
				return reportdb.RUAAuthorized // same-domain rua needs no external authorization
			}
			accepts, status, _, _, _, err := dmarc.LookupExternalReportsAccepted(ctx, nil, reportResolver, rd, ruaDomain)
			if accepts && err == nil {
				return reportdb.RUAAuthorized
			}
			if status == dmarc.StatusTemperror {
				return reportdb.RUATransient // retry next tick, don't drop the window
			}
			return reportdb.RUADenied
		}
		repCoord := ha.NewCoordinator(ha.New(s.Pool, reportLeaderKey, cfg.nodeID), cfg.reportInterval)
		repCoord.OnElected = func(context.Context) { log.Info("elected dmarc-report leader", "node", cfg.nodeID) }
		repCoord.OnLost = func() { log.Info("lost dmarc-report leadership", "node", cfg.nodeID) }
		repCoord.Tick = func(ctx context.Context) {
			domains, err := reports.UnreportedDMARCDomains(ctx)
			if err != nil {
				log.Warn("dmarc report: list domains", "err", err)
				return
			}
			leader := repCoord.Leader()
			for _, d := range domains {
				sent, err := reports.SendDMARCReportFenced(ctx, leader.FenceExec, ruaAuthorized, submitter,
					sysTenantID, sysAccountID, d, orgDomain, orgEmail)
				if err != nil {
					if errors.Is(err, ha.ErrFenced) {
						// Lost leadership mid-run; stop — the new leader takes over.
						return
					}
					log.Warn("dmarc report send", "domain", d, "err", err)
					continue
				}
				if sent {
					log.Info("dmarc aggregate report sent", "domain", d)
				}
			}
		}
		go repCoord.Run(ctx)
	}

	// Webhook delivery worker.
	whWorker := &deliverability.WebhookWorker{Pool: s.Pool, NodeID: cfg.nodeID, Batch: 50, Secret: cfg.webhookSecret, Log: log}
	drain.goLoop(ctx, log, "webhook-worker", cfg.queueInterval, func() {
		if n, err := whWorker.RunOnce(ctx); err != nil {
			log.Warn("webhook worker", "err", err)
		} else if n > 0 {
			log.Info("webhook worker delivered", "count", n)
		}
	})

	log.Info("octo-mail node up", "node", cfg.nodeID)

	// Wait for shutdown or a fatal listener error, then drain gracefully.
	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down; draining in-flight work", "timeout", cfg.drainTimeout)
	case err := <-errc:
		runErr = err
		log.Warn("fatal listener error; shutting down", "err", err)
	}
	// Stop accepting and let in-flight requests + worker iterations finish, bounded
	// by the drain timeout. ctx is already cancelled on the ctx.Done() path; on the
	// errc path, cancel it so listeners/workers begin winding down before we wait.
	stop()
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.drainTimeout)
	defer cancel()
	drain.shutdown(drainCtx, log)
	log.Info("drain complete")
	return runErr
}

// serveTCPListener serves on a pre-bound listener when ln != nil (used by the
// privsep path, which binds privileged ports before dropping root); otherwise it
// binds addr itself.
func serveTCPListener(ctx context.Context, log *slog.Logger, name, addr string, ln net.Listener, errc chan<- error, maxConns int, drain *drainSet, handle func(net.Conn)) {
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			errc <- fmt.Errorf("%s listen %s: %w", name, addr, err)
			return
		}
	}
	log.Info("listening", "service", name, "addr", ln.Addr().String())
	go func() { <-ctx.Done(); _ = ln.Close() }()
	// sem bounds concurrent connections per listener so a flood of connections
	// (each of which may buffer a whole message) can't exhaust memory/goroutines.
	// A nil sem (maxConns <= 0) disables the cap.
	var sem chan struct{}
	if maxConns > 0 {
		sem = make(chan struct{}, maxConns)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			log.Warn("accept", "service", name, "err", err)
			continue
		}
		// A connection already in the kernel accept queue can be returned AFTER
		// ctx was cancelled but before the async ln.Close() fires. Admitting it
		// would both let a new connection into a drain that is supposed to have
		// stopped accepting, and — worse — call drain.track()'s wg.Add(1)
		// concurrently with the shutdown path's wg.Wait(), which panics
		// ("WaitGroup misuse: Add called concurrently with Wait"). Re-check here
		// and refuse promptly.
		if ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				// At capacity: refuse fast rather than queue unboundedly.
				log.Warn("connection cap reached, refusing", "service", name, "max", maxConns)
				_ = conn.Close()
				continue
			}
		}
		// Track the handler so a graceful shutdown awaits in-flight connections
		// (up to the drain deadline) instead of cutting them off mid-request.
		drain.track(func() {
			if sem != nil {
				defer func() { <-sem }()
			}
			handle(conn)
		})
	}
}

// serveHTTP runs an http.Server behind the same per-listener connection cap as
// the TCP front doors and with slowloris-defeating timeouts. The JMAP/webmail and
// admin HTTP listeners would otherwise be the only entry doors without a
// connection cap, and MaxBytesReader/body caps don't fire until a request fully
// arrives — so a trickle of headers could hold goroutines/FDs indefinitely.
//
// preboundLn, when non-nil, is a listener bound before privilege drop (privsep) —
// used for the ACME HTTPS listener on the privileged :443. When srv.TLSConfig is
// set, the listener is wrapped in TLS (so the same door serves HTTPS and, via the
// config's acme-tls/1 NextProto, answers tls-alpn-01 challenges).
func serveHTTP(log *slog.Logger, name string, srv *http.Server, maxConns int, drain *drainSet, preboundLn net.Listener, errc chan<- error) {
	// Timeouts bound how long a slow client can hold a connection before its
	// request completes (headers, whole request, and idle keep-alive).
	if srv.ReadHeaderTimeout == 0 {
		srv.ReadHeaderTimeout = 10 * time.Second
	}
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = 60 * time.Second
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = 120 * time.Second
	}
	// Register for graceful Shutdown at drain time (replaces an abrupt Close).
	drain.addServer(srv)
	ln := preboundLn
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", srv.Addr)
		if err != nil {
			errc <- fmt.Errorf("%s listen %s: %w", name, srv.Addr, err)
			return
		}
	}
	if maxConns > 0 {
		ln = &limitListener{Listener: ln, sem: make(chan struct{}, maxConns)}
	}
	// TLS wrap AFTER the conn cap so the cap still applies to TLS connections. The
	// serving config's GetCertificate obtains/serves certs (and answers tls-alpn-01).
	if srv.TLSConfig != nil {
		ln = tls.NewListener(ln, srv.TLSConfig)
	}
	log.Info("listening", "service", name, "addr", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errc <- fmt.Errorf("%s: %w", name, err)
	}
}

// limitListener caps the number of concurrent accepted connections; a slot is
// released when the connection is closed. Unlike the TCP front doors' refuse-fast
// semaphore, an HTTP listener blocks in Accept when full (returning an error from
// Accept would tear the server down), so excess connections wait for a slot.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{} // blocks until a slot is free
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: l.sem}, nil
}

// limitConn releases its listener slot exactly once, on Close.
type limitConn struct {
	net.Conn
	release chan struct{}
	once    sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.release })
	return err
}

// drainSet coordinates a graceful shutdown drain: it tracks the HTTP servers to
// Shutdown and a WaitGroup for in-flight connection handlers and worker-loop
// iterations, so on SIGTERM the process stops accepting new work but lets
// in-progress requests/iterations finish (up to a deadline) instead of being cut
// off mid-flight. Methods are goroutine-safe.
type drainSet struct {
	mu      sync.Mutex
	servers []*http.Server
	wg      sync.WaitGroup
}

func (d *drainSet) addServer(srv *http.Server) {
	d.mu.Lock()
	d.servers = append(d.servers, srv)
	d.mu.Unlock()
}

// track wraps a unit of drainable work: increment before it starts, decrement
// when it returns. Used for connection handlers and worker loops.
func (d *drainSet) track(fn func()) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		fn()
	}()
}

// shutdown stops accepting and waits (bounded by drainCtx) for tracked work to
// finish. It Shutdown()s every registered HTTP server (graceful: stop accepting,
// let active requests complete) and awaits the connection/worker WaitGroup.
func (d *drainSet) shutdown(drainCtx context.Context, log *slog.Logger) {
	d.mu.Lock()
	servers := append([]*http.Server(nil), d.servers...)
	d.mu.Unlock()
	for _, srv := range servers {
		if err := srv.Shutdown(drainCtx); err != nil {
			log.Warn("http graceful shutdown", "addr", srv.Addr, "err", err)
		}
	}
	// Await tracked conns + worker iterations, bounded by drainCtx.
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-drainCtx.Done():
		log.Warn("drain deadline exceeded; some in-flight work was not awaited")
	}
}

// goLoop starts a tracked runLoop: because runLoop returns only after ctx is
// cancelled AND its current fn() has finished, awaiting the tracked goroutine at
// shutdown awaits the in-flight iteration (e.g. a queue RunOnce), so a worker
// isn't torn down mid-batch.
func (d *drainSet) goLoop(ctx context.Context, log *slog.Logger, name string, interval time.Duration, fn func()) {
	d.track(func() { runLoop(ctx, log, name, interval, fn) })
}

// runLoop calls fn every interval until ctx is done.
func runLoop(ctx context.Context, log *slog.Logger, name string, interval time.Duration, fn func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// projectionDrainer advances the FTS + threading projections across accounts,
// paginated and cancellable. It keeps a round-robin cursor across ticks so each
// tick does a bounded amount of work (at most pageSize accounts) and no account is
// starved: the cursor wraps to 0 after the last account. Serial within a tick, but
// bounded — a huge account table no longer means one unbounded, uncancellable scan.
type projectionDrainer struct {
	s       *postgres.Store
	fts     *projection.FTSWorker
	threads *projection.ThreadWorker
	log     *slog.Logger

	pageSize int
	cursor   int64 // last account id processed; next tick resumes after it
}

func (d *projectionDrainer) tick(ctx context.Context) {
	rows, err := d.s.Pool.Query(ctx,
		`SELECT id, tenant_id FROM accounts WHERE NOT disabled AND id > $1 ORDER BY id LIMIT $2`,
		d.cursor, d.pageSize)
	if err != nil {
		d.log.Warn("projection: list accounts", "err", err)
		return
	}
	type acct struct{ id, tenant int64 }
	var accts []acct
	for rows.Next() {
		var a acct
		if err := rows.Scan(&a.id, &a.tenant); err != nil {
			rows.Close()
			d.log.Warn("projection: scan account", "err", err)
			return
		}
		accts = append(accts, a)
	}
	rows.Close()
	if len(accts) == 0 {
		d.cursor = 0 // wrapped past the last account; restart the round-robin next tick
		return
	}
	for _, a := range accts {
		// Return promptly on shutdown so the coordinator loop can exit and resign.
		if ctx.Err() != nil {
			return
		}
		if err := d.fts.DrainAccount(ctx, a.tenant, a.id); err != nil {
			d.log.Warn("fts drain", "account", a.id, "err", err)
		}
		if err := d.threads.DrainAccount(ctx, a.tenant, a.id); err != nil {
			d.log.Warn("thread drain", "account", a.id, "err", err)
		}
		// Backfill summary columns for rows that predate them (in-place upgrade):
		// the forward drain above only folds new rows, so legacy rows need this
		// one-time-per-row pass or filtered search would omit all historical mail.
		if err := d.threads.BackfillSummaries(ctx, a.tenant, a.id); err != nil {
			d.log.Warn("summary backfill", "account", a.id, "err", err)
		}
		d.cursor = a.id // advance so the next tick resumes after this account
	}
}

// resolveMX resolves a recipient domain to the ordered list of MX candidates to
// try, for connection failover: MX records sorted by ascending preference, with
// equal-preference hosts shuffled (RFC 5321 §5.1, to spread load and avoid always
// hammering the same host). Falls back to the domain's own A/AAAA (an implicit MX
// at pref 0) when there are no MX records. Each candidate dials the host on port 25.
func resolveMX(ctx context.Context, domain string) ([]submit.MXHost, error) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		// Distinguish a definitive "no MX records" (NXDOMAIN / no such host) from a
		// TEMPORARY DNS failure. On tempfail, return the error so the queue defers and
		// retries rather than silently falling back to the domain's A/AAAA — which
		// could deliver to the wrong host (or bypass a legitimate MX) during a DNS
		// blip. Only a definitive no-records answer falls through to the implicit MX.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsTemporary {
			return nil, fmt.Errorf("mx lookup for %s (temporary): %w", domain, err)
		}
		// Definitive negative (or a non-DNSError we can't classify as temporary):
		// treat as no MX and fall back to the implicit MX below.
	}
	if err != nil || len(mxs) == 0 {
		// No usable MX: fall back to the domain itself (implicit MX).
		return []submit.MXHost{{Host: dns.Domain{ASCII: domain}, Addr: net.JoinHostPort(domain, "25")}}, nil
	}
	// LookupMX returns records sorted by Pref; shuffle within each equal-preference
	// run so we don't always pick the same host among equals, then keep the runs in
	// ascending-preference order.
	sorted := make([]*net.MX, len(mxs))
	copy(sorted, mxs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Pref < sorted[j].Pref })
	for i := 0; i < len(sorted); {
		j := i + 1
		for j < len(sorted) && sorted[j].Pref == sorted[i].Pref {
			j++
		}
		if j-i > 1 {
			run := sorted[i:j]
			rand.Shuffle(len(run), func(a, b int) { run[a], run[b] = run[b], run[a] })
		}
		i = j
	}
	out := make([]submit.MXHost, 0, len(sorted))
	for _, mx := range sorted {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			continue
		}
		out = append(out, submit.MXHost{Host: dns.Domain{ASCII: host}, Addr: net.JoinHostPort(host, "25")})
	}
	if len(out) == 0 {
		out = append(out, submit.MXHost{Host: dns.Domain{ASCII: domain}, Addr: net.JoinHostPort(domain, "25")})
	}
	return out, nil
}

func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "@"); i >= 0 {
		if j := strings.Index(dsn, "://"); j >= 0 && j+3 < i {
			return dsn[:j+3] + "***@" + dsn[i+1:]
		}
	}
	return dsn
}
