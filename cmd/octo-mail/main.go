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
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/Mininglamp-OSS/octo-mail/webui"
	"github.com/mjl-/mox/dns"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Blob store: S3 if configured, else local filesystem.
	var bs blob.Store
	var err error
	if cfg.s3Endpoint != "" {
		bs, err = blob.NewS3(blob.S3Config{
			Endpoint:  cfg.s3Endpoint,
			Region:    cfg.s3Region,
			Bucket:    cfg.s3Bucket,
			AccessKey: cfg.s3Access,
			SecretKey: cfg.s3Secret,
		})
		if err != nil {
			return fmt.Errorf("s3 blob store: %w", err)
		}
		log.Info("blob store", "backend", "s3", "endpoint", cfg.s3Endpoint, "bucket", cfg.s3Bucket)
	} else {
		bs, err = blob.NewFS(cfg.blobDir)
		if err != nil {
			return fmt.Errorf("fs blob store: %w", err)
		}
		log.Info("blob store", "backend", "fs", "dir", cfg.blobDir)
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
	repo := &deliverability.Service{Pool: s.Pool}
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

	// Privilege separation: when OCTO_MAIL_RUN_AS is set, bind all privileged TCP
	// ports while still root, then irreversibly drop to the unprivileged user
	// before serving any client (the root→unprivileged-user model, done in-process).
	prebound := map[string]net.Listener{}
	if spec := os.Getenv("OCTO_MAIL_RUN_AS"); spec != "" {
		ids, err := privsep.ResolveUser(spec)
		if err != nil {
			return fmt.Errorf("privsep: %w", err)
		}
		addrs := map[string]string{
			"smtp-mx":         cfg.smtpAddr,
			"smtp-submission": cfg.submissionAddr,
			"imap":            cfg.imapAddr,
		}
		prebound, err = privsep.Sequence(addrs, ids, privsep.DropPrivileges)
		if err != nil {
			return fmt.Errorf("privsep: %w", err)
		}
		log.Info("privilege separation: bound privileged ports, dropped to unprivileged user", "uid", ids.UID, "gid", ids.GID)
	}

	// Optional ACME/autotls: when configured, listeners can use automatic certs.
	// Real issuance needs a reachable ACME directory + challenge reachability
	// (deployment-layer); here we construct the manager and expose its TLS config.
	var acmeTLS *tls.Config
	if cfg.acmeDirectory != "" && cfg.acmeContact != "" {
		am, err := acme.New(acme.Config{
			CacheDir:     cfg.acmeCacheDir,
			ContactEmail: cfg.acmeContact,
			DirectoryURL: cfg.acmeDirectory,
			Hostnames:    cfg.acmeHosts,
			Fallback:     dns.Domain{ASCII: cfg.hostname},
			Shutdown:     ctx.Done(),
		})
		if err != nil {
			return fmt.Errorf("acme: %w", err)
		}
		acmeTLS = am.TLSConfig()
		log.Info("ACME/autotls enabled", "directory", cfg.acmeDirectory, "hosts", cfg.acmeHosts)
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

	// Per-account junk filter (bayesian), routing spam to the Junk mailbox.
	junkMgr := junkfilter.NewManager(cfg.junkDir, junkfilter.DefaultParams, cfg.junkThreshold)
	defer junkMgr.Close()

	// SMTP receive (MX, :25).
	if cfg.smtpAddr != "" {
		vacation := &autoreply.Responder{Lookup: s.LookupAccountByID, Submitter: submitter}
		mx := &smtpd.Server{Dir: dir, Hostname: cfg.hostname, MaxSize: cfg.maxSize, TLSConfig: nil, Auth: authenticator, RejectDMARCFail: cfg.rejectDMARC, Junk: junkMgr, Decider: decider,
			DMARCRecorder: func(ctx context.Context, fromDomain, sourceIP, spf, dkim, disposition string) {
				_ = reports.RecordDMARCAgg(ctx, fromDomain, "", sourceIP, spf, dkim, disposition)
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
			if err := checkVERPConfig(cfg); err != nil {
				return err
			}
			if len(cfg.verpKey) == 0 {
				log.Warn("VERP signing key not set (OCTO_MAIL_VERP_KEY); bounce/complaint attribution is forgeable — dev-only unsigned path enabled via OCTO_MAIL_ALLOW_UNSIGNED_VERP", "bounce_domain", cfg.bounceDomain)
			}
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
		go serveTCPListener(ctx, log, "smtp-mx", cfg.smtpAddr, prebound["smtp-mx"], errc, func(nc net.Conn) { _ = mx.Serve(ctx, nc) })
	}
	// SMTP submission (:587).
	if cfg.submissionAddr != "" {
		sub := &smtpd.Server{Dir: dir, Hostname: cfg.hostname, MaxSize: cfg.maxSize, Submission: submitter}
		// BURL (RFC 4468): resolve an authorized IMAP URL to message bytes within
		// the submitting account, reusing the IMAP URLAUTH validator.
		sub.BURLResolver = func(ctx context.Context, accountID int64, authURL string) ([]byte, bool) {
			acc, _, _, err := s.LookupAccountByID(ctx, accountID)
			if err != nil {
				return nil, false
			}
			return imapd.ResolveURLAuth(ctx, acc, authURL)
		}
		go serveTCPListener(ctx, log, "smtp-submission", cfg.submissionAddr, prebound["smtp-submission"], errc, func(nc net.Conn) { _ = sub.Serve(ctx, nc) })
	}
	// IMAP (:143).
	if cfg.imapAddr != "" {
		imap := &imapd.Server{Dir: dir, Junk: junkMgr, TLSConfig: acmeTLS}
		go serveTCPListener(ctx, log, "imap", cfg.imapAddr, prebound["imap"], errc, func(nc net.Conn) { _ = imap.Serve(ctx, nc) })
	}
	// JMAP (HTTP) + webmail SPA (same origin, so the SPA's /jmap/* fetches work).
	if cfg.jmapAddr != "" {
		js := &jmapd.Server{Dir: dir, BaseURL: cfg.jmapBaseURL, Submission: submitter, Blob: bs}
		wa := &webapi.Server{Dir: dir, Submission: submitter, Suppressions: &deliverability.Suppressions{Pool: s.Pool}}
		mux := http.NewServeMux()
		mux.Handle("/jmap/", js.Handler())
		mux.Handle("/webapi/", wa.Handler())
		mux.Handle("/webmail", webui.Handler())
		mux.Handle("/webmail/", webui.Handler())
		srv := &http.Server{Addr: cfg.jmapAddr, Handler: mux}
		go func() {
			log.Info("listening", "service", "jmap+webmail", "addr", cfg.jmapAddr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("jmap: %w", err)
			}
		}()
		go func() { <-ctx.Done(); _ = srv.Close() }()
	}
	// Admin/account API + healthz (HTTP).
	if cfg.adminAddr != "" {
		// Operators failing a queued message from the admin API bounce it back to
		// the sender via the same DSN generator the worker uses at max attempts.
		failDSN := &submit.DSNGenerator{Opener: s, Hostname: dns.Domain{ASCII: cfg.hostname}, Blob: bs}
		as := &webadmin.Server{Pool: s.Pool, Dir: dir, Reputation: repo, AdminToken: cfg.adminToken,
			QueueFailDSN: failDSN.Generate}
		srv := &http.Server{Addr: cfg.adminAddr, Handler: as.Handler()}
		go func() {
			log.Info("listening", "service", "admin", "addr", cfg.adminAddr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("admin: %w", err)
			}
		}()
		go func() { <-ctx.Done(); _ = srv.Close() }()
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
		Backoff: cfg.queueBackoff, DelayThreshold: cfg.queueDelayDSN, RetiredKeep: cfg.queueRetKeep,
		ObserveDelivery: func(d time.Duration, result string) {
			obs.QueueDeliveryDuration.WithLabelValues(result).Observe(d.Seconds())
		},
		OnDelayed: func(ctx context.Context, m queue.Msg) error {
			// Retried enough times to warrant telling the sender we're still trying.
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "delayed",
				map[string]any{"rcpt": m.RcptTo, "msgid": m.ID, "attempts": m.Attempts})
			return nil
		},
		OnFailed: func(ctx context.Context, m queue.Msg) error {
			// Permanent failure: suppress the recipient, record a bounce for
			// reputation, and emit a webhook. Best-effort; errors are logged.
			if err := suppress.Add(ctx, m.TenantID, m.AccountID, m.RcptTo, "hard bounce (max attempts)"); err != nil {
				log.Warn("suppress on bounce", "err", err)
			}
			dom := ""
			if at := strings.LastIndexByte(m.RcptTo, '@'); at >= 0 {
				dom = m.RcptTo[at+1:]
			}
			if dom != "" {
				// Delivery-time hard bounce: no single signed msgID to dedup on, so
				// pass 0 (non-idempotent — these are our own authenticated events).
				_ = repo.RecordEvent(ctx, m.TenantID, m.AccountID, deliverability.KindBounce, dom, 0)
			}
			_ = webhooks.Enqueue(ctx, m.TenantID, m.AccountID, cfg.webhookURL, "bounced",
				map[string]any{"rcpt": m.RcptTo, "msgid": m.ID})
			return nil
		},
	}
	go runLoop(ctx, log, "queue-worker", cfg.queueInterval, func() {
		if n, err := worker.RunOnce(ctx); err != nil {
			log.Warn("queue worker", "err", err)
		} else if n > 0 {
			log.Info("queue worker delivered", "count", n)
		}
	})

	// Retired-message retention sweep: drop retired queue rows (and their results)
	// past keep_until. Safe on every node (a plain DELETE by time); hourly is fine.
	go runLoop(ctx, log, "queue-cleanup", time.Hour, func() {
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
	go runLoop(ctx, log, "blob-gc", time.Hour, func() {
		rows, blobs, err := s.CollectGarbage(ctx, 1000)
		if err != nil {
			log.Warn("blob gc", "err", err)
		} else if rows > 0 || blobs > 0 {
			log.Info("blob gc", "rows_deleted", rows, "blobs_removed", blobs)
		}
	})

	// Queue depth gauge sampler: publish due/held/total to Prometheus each tick.
	// Safe on every node (a read-only aggregate); the scraper sees the latest value.
	go runLoop(ctx, log, "queue-depth", 15*time.Second, func() {
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
	threads := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 100}
	const projLeaderKey = int64(0x6f63746f6d61696c) // "octomail"
	projCoord := ha.NewCoordinator(ha.New(s.Pool, projLeaderKey), cfg.projInterval)
	projCoord.OnElected = func(context.Context) { log.Info("elected projection-drain leader", "node", cfg.nodeID) }
	projCoord.OnLost = func() { log.Info("lost projection-drain leadership", "node", cfg.nodeID) }
	projCoord.Tick = func(ctx context.Context) { drainProjections(ctx, log, s, fts, threads) }
	go projCoord.Run(ctx)

	// Daily IP-warmup maintenance, when an egress pool is configured. This MUST be
	// a cluster singleton (it resets/advances shared per-IP counters), so it is
	// leader-gated via its own coordinator — never run per-node. Without it,
	// sent_today never resets and every warming IP wedges at its stage-0 cap,
	// deferring then bouncing all egress-pool deliveries within a day or two.
	if cfg.egressPool {
		ipr := &deliverability.IPRouter{Pool: s.Pool}
		const warmupLeaderKey = int64(0x6f6d5f77726d70) // "om_wrmp"
		warmCoord := ha.NewCoordinator(ha.New(s.Pool, warmupLeaderKey), time.Hour)
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

	// Webhook delivery worker.
	whWorker := &deliverability.WebhookWorker{Pool: s.Pool, NodeID: cfg.nodeID, Batch: 50}
	go runLoop(ctx, log, "webhook-worker", cfg.queueInterval, func() {
		if n, err := whWorker.RunOnce(ctx); err != nil {
			log.Warn("webhook worker", "err", err)
		} else if n > 0 {
			log.Info("webhook worker delivered", "count", n)
		}
	})

	log.Info("octo-mail node up", "node", cfg.nodeID)

	// Wait for shutdown or a fatal listener error.
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		return nil
	case err := <-errc:
		return err
	}
}

// serveTCPListener serves on a pre-bound listener when ln != nil (used by the
// privsep path, which binds privileged ports before dropping root); otherwise it
// binds addr itself.
func serveTCPListener(ctx context.Context, log *slog.Logger, name, addr string, ln net.Listener, errc chan<- error, handle func(net.Conn)) {
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			log.Warn("accept", "service", name, "err", err)
			continue
		}
		go handle(conn)
	}
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

// drainProjections advances FTS + threading for every account that has fallen
// behind (a projection cursor below the account head, or no cursor yet).
func drainProjections(ctx context.Context, log *slog.Logger, s *postgres.Store, fts *projection.FTSWorker, threads *projection.ThreadWorker) {
	rows, err := s.Pool.Query(ctx, `SELECT id, tenant_id FROM accounts WHERE NOT disabled`)
	if err != nil {
		log.Warn("projection: list accounts", "err", err)
		return
	}
	type acct struct{ id, tenant int64 }
	var accts []acct
	for rows.Next() {
		var a acct
		if err := rows.Scan(&a.id, &a.tenant); err != nil {
			rows.Close()
			log.Warn("projection: scan account", "err", err)
			return
		}
		accts = append(accts, a)
	}
	rows.Close()
	for _, a := range accts {
		if err := fts.DrainAccount(ctx, a.tenant, a.id); err != nil {
			log.Warn("fts drain", "account", a.id, "err", err)
		}
		if err := threads.DrainAccount(ctx, a.tenant, a.id); err != nil {
			log.Warn("thread drain", "account", a.id, "err", err)
		}
	}
}

// resolveMX performs minimal MX resolution: try MX records, fall back to the
// domain A record; the connect address is the chosen host on port 25.
func resolveMX(ctx context.Context, domain string) (dns.Domain, string, error) {
	host := domain
	if mxs, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil && len(mxs) > 0 {
		host = strings.TrimSuffix(mxs[0].Host, ".")
	}
	return dns.Domain{ASCII: host}, net.JoinHostPort(host, "25"), nil
}

func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "@"); i >= 0 {
		if j := strings.Index(dsn, "://"); j >= 0 && j+3 < i {
			return dsn[:j+3] + "***@" + dsn[i+1:]
		}
	}
	return dsn
}
