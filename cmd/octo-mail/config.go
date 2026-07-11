package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// openBlobStore builds the message blob store from config: S3 when an endpoint is
// configured, else the local filesystem. It is the single source of truth so the
// serve process (run) and every ops subcommand that touches bodies (export,
// import, passwd) agree on the backend — otherwise a backup/restore on an S3
// deployment silently reads/writes an empty local ./blobs.
func openBlobStore(cfg config, log *slog.Logger) (blob.Store, error) {
	if cfg.s3Endpoint != "" {
		bs, err := blob.NewS3(blob.S3Config{
			Endpoint:     cfg.s3Endpoint,
			Region:       cfg.s3Region,
			Bucket:       cfg.s3Bucket,
			AccessKey:    cfg.s3Access,
			SecretKey:    cfg.s3Secret,
			SessionToken: cfg.s3SessionToken,
		})
		if err != nil {
			return nil, fmt.Errorf("s3 blob store: %w", err)
		}
		log.Info("blob store", "backend", "s3", "endpoint", cfg.s3Endpoint, "bucket", cfg.s3Bucket)
		return bs, nil
	}
	bs, err := blob.NewFS(cfg.blobDir)
	if err != nil {
		return nil, fmt.Errorf("fs blob store: %w", err)
	}
	log.Info("blob store", "backend", "fs", "dir", cfg.blobDir)
	log.Warn("fs blob backend is SINGLE-NODE only: message bodies live on this node's local disk and are not visible to other nodes; use OCTO_MAIL_S3_ENDPOINT for a multi-node deployment")
	return bs, nil
}

// checkVERPConfig refuses a bounce domain configured without a signing key: that
// combination accepts unsigned VERP tokens, which anyone can forge to attribute
// bounces/complaints to a victim tenant (cross-tenant reputation DoS) — the exact
// hole VERP exists to close. Rather than silently fail open, startup fails unless
// the operator explicitly opts into the unsigned path (local dev). Returns nil
// when VERP is disabled, signed, or the escape hatch is set.
func checkVERPConfig(cfg config) error {
	if cfg.bounceDomain == "" || len(cfg.verpKey) > 0 || cfg.allowUnsignedVERP {
		return nil
	}
	return fmt.Errorf("OCTO_MAIL_BOUNCE_DOMAIN is set but OCTO_MAIL_VERP_KEY is empty: " +
		"bounce/complaint attribution would be forgeable (cross-tenant reputation DoS). " +
		"Set OCTO_MAIL_VERP_KEY, or set OCTO_MAIL_ALLOW_UNSIGNED_VERP=1 to allow the unsigned path (dev only)")
}

// checkReporterConfig validates the report role: outbound aggregate reports carry
// this node's identity (org domain/email derived from hostname) to third parties,
// so the default placeholder hostname would emit reports as "octo-mail.local" —
// refuse it at startup rather than send misattributed mail.
func checkReporterConfig(cfg config) error {
	if !cfg.reporter {
		return nil
	}
	if cfg.hostname == "" || cfg.hostname == "octo-mail.local" {
		return fmt.Errorf("OCTO_MAIL_REPORTER=1 requires a real OCTO_MAIL_HOSTNAME: " +
			"outbound DMARC reports are addressed as dmarc-reports@<hostname> and sent to third parties; " +
			"the default 'octo-mail.local' would misattribute them")
	}
	// Inbound report ingestion routes RCPT by domain, and the RCPT dispatch checks
	// the bounce domain BEFORE the report domain. If they collide, all report mail
	// is swallowed by the bounce handler and silently never ingested — refuse it.
	if cfg.reportDomain != "" && cfg.bounceDomain != "" && cfg.reportDomain == cfg.bounceDomain {
		return fmt.Errorf("OCTO_MAIL_REPORT_DOMAIN must differ from OCTO_MAIL_BOUNCE_DOMAIN "+
			"(both %q): report mail to a shared domain would be routed to the bounce handler and never ingested",
			cfg.reportDomain)
	}
	return nil
}

// validate performs 12-factor-style startup checks that the per-role check
// functions above don't cover: it FAILS FAST on a misconfiguration that would
// otherwise surface only at first use, and WARNS on settings that are silently
// lenient today (unparseable env values folded to defaults; an unauthenticated
// admin listener on a non-loopback address). Called once in run() after the other
// check* functions. Warnings need the logger; errors abort startup.
func validate(cfg config, log *slog.Logger) error {
	// Fail fast: an S3 endpoint with NO credential path at all. Empty static creds
	// ARE legitimate when a session token is set (STS) or an ambient IAM role is
	// expected — but endpoint set with access+secret+token all empty is almost
	// certainly a misconfiguration that would fail only on the first S3 request.
	if cfg.s3Endpoint != "" && cfg.s3Access == "" && cfg.s3Secret == "" && cfg.s3SessionToken == "" {
		return fmt.Errorf("OCTO_MAIL_S3_ENDPOINT is set (%q) but no credentials are configured: "+
			"set OCTO_MAIL_S3_ACCESS + OCTO_MAIL_S3_SECRET, or OCTO_MAIL_S3_SESSION_TOKEN for STS/IAM-role auth",
			cfg.s3Endpoint)
	}

	// Warn: the admin API on a non-loopback address without a token. The default
	// ":8081" binds all interfaces; with no token that exposes admin operations to
	// anything that can reach the node.
	if cfg.adminToken == "" && !isLoopbackAddr(cfg.adminAddr) {
		log.Warn("admin API listens on a non-loopback address with no OCTO_MAIL_ADMIN_TOKEN: "+
			"admin operations are unauthenticated and reachable off-host. Set OCTO_MAIL_ADMIN_TOKEN, "+
			"or bind OCTO_MAIL_ADMIN_ADDR to loopback (e.g. 127.0.0.1:8081)", "admin_addr", cfg.adminAddr)
	}

	// Warn: env values that were set but didn't parse, so an operator sees the typo
	// instead of silently getting the default. The load helpers fold a parse error
	// to the default (no behavior change); this re-checks the raw strings.
	for _, k := range []string{
		"OCTO_MAIL_MAX_SIZE", "OCTO_MAIL_MAX_CONNS", "OCTO_MAIL_QUEUE_DELAY_DSN", "OCTO_MAIL_MAX_HOPS",
		"OCTO_MAIL_TRUSTED_HAM_COUNT", "OCTO_MAIL_SEND_RATE_MAX",
	} {
		if v := os.Getenv(k); v != "" {
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				log.Warn("ignoring unparseable integer env value; using default", "env", k, "value", v)
			}
		}
	}
	for _, k := range []string{
		"OCTO_MAIL_DRAIN_TIMEOUT", "OCTO_MAIL_REPORT_INTERVAL", "OCTO_MAIL_QUEUE_INTERVAL",
		"OCTO_MAIL_PROJECTION_INTERVAL", "OCTO_MAIL_QUEUE_BACKOFF", "OCTO_MAIL_QUEUE_MAX_BACKOFF",
		"OCTO_MAIL_QUEUE_MAX_LIFETIME", "OCTO_MAIL_QUEUE_RETIRED_KEEP", "OCTO_MAIL_GREYLIST_DELAY",
		"OCTO_MAIL_SUBJECTPASS_PERIOD", "OCTO_MAIL_SEND_RATE_WINDOW",
	} {
		if v := os.Getenv(k); v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				log.Warn("ignoring unparseable duration env value; using default", "env", k, "value", v)
			}
		}
	}
	for _, k := range []string{"OCTO_MAIL_JUNK_THRESHOLD", "OCTO_MAIL_REJECT_THRESHOLD"} {
		if v := os.Getenv(k); v != "" {
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				log.Warn("ignoring unparseable float env value; using default", "env", k, "value", v)
			}
		}
	}
	return nil
}

// isLoopbackAddr reports whether a "host:port" listen address binds only the
// loopback interface. An empty host (":8081") or 0.0.0.0/:: binds ALL interfaces
// (not loopback). A named "localhost" is treated as loopback. Used to decide
// whether an unauthenticated admin listener is exposed off-host.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port; treat the whole thing as the host
	}
	if host == "" {
		return false // ":8081" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// A non-IP, non-localhost hostname: can't prove it's loopback → treat as exposed.
	return false
}

// config is the node's runtime configuration, loaded from the environment.
type config struct {
	dsn      string
	nodeID   string
	hostname string
	maxSize  int64
	// maxConns caps concurrent connections per TCP listener (smtp-mx, submission,
	// imap). Each connection may buffer a whole message (up to maxSize), so an
	// unbounded goroutine-per-connection accept loop is an OOM/DoS vector; this
	// bounds peak memory ≈ maxConns × maxSize per listener. 0 = unlimited.
	maxConns int

	// drainTimeout bounds the graceful-shutdown drain: on SIGTERM the node stops
	// accepting and waits up to this long for in-flight requests + worker iterations
	// to finish before exiting.
	drainTimeout time.Duration

	// bounceDomain, when set, enables VERP: outbound deliveries use an envelope
	// MAIL FROM of bounces+<tenant>.<msg>.<mac>@<bounceDomain>, and inbound mail to
	// that domain is routed to complaint/bounce handling (ARF + DSN) → reputation.
	// Requires the operator to publish SPF/MX for the bounce domain pointing at
	// this server. Empty = VERP disabled (envelope unchanged).
	bounceDomain string
	// verpKey signs VERP tokens (HMAC) so an unauthenticated sender cannot forge a
	// bounce/complaint attributed to a victim tenant. Strongly recommended when
	// bounceDomain is set; empty falls back to unsigned tokens (dev only, and
	// refused at startup unless allowUnsignedVERP is set — see below).
	verpKey []byte
	// allowUnsignedVERP is the explicit dev escape hatch that permits enabling the
	// bounce domain WITHOUT a signing key. Without it, bounceDomain+empty verpKey
	// is a fatal misconfiguration rather than a silent fail-open onto the forgeable
	// unsigned attribution path (a security control, not a warning).
	allowUnsignedVERP bool

	// reporter, when true, enables the RFC 7489/8460 report ROLE: a leader-gated
	// scheduler that generates+sends outbound DMARC aggregate reports, and an MX
	// hook that ingests inbound reports addressed to reportDomain. Off by default —
	// it sends mail to third parties, so it is opt-in. Requires a real (non-default)
	// hostname for the report org identity.
	reporter bool
	// reportInterval is the outbound report scheduler cadence (leader-gated).
	reportInterval time.Duration
	// reportDomain is the domain of this node's inbound report address; mail to it
	// is parsed and ingested instead of delivered (mirrors bounceDomain). Empty
	// disables inbound ingestion even when reporter is true.
	reportDomain string

	blobDir string // fs blob store dir (used when s3Endpoint is empty)

	s3Endpoint string
	s3Region   string
	s3Bucket   string
	s3Access   string
	s3Secret   string
	// s3SessionToken is an optional STS/IAM-role temporary-credential token.
	s3SessionToken string

	smtpAddr       string
	submissionAddr string
	imapAddr       string
	jmapAddr       string
	jmapBaseURL    string

	queueInterval    time.Duration
	projInterval     time.Duration
	queueBackoff     time.Duration // base retry delay; doubles per attempt (capped at queueMaxBackoff)
	queueMaxBackoff  time.Duration // cap on a single retry interval (Postfix maximal_backoff_time)
	queueMaxLifetime time.Duration // give up on a message older than this (Postfix maximal_queue_lifetime)
	queueDelayDSN    int           // attempts before a "still trying" warning DSN (0=off)
	queueRetKeep     time.Duration // how long to keep retired queue messages before cleanup

	dnsblZones  []dns.Domain
	rejectDMARC bool
	maxHops     int // inbound Received-header loop limit (0 = smtpd default)
	greylist    bool

	junkThreshold float64

	// Inbound decision-engine tuning (all optional; zero uses Decider defaults).
	greylistDelay     time.Duration
	rejectThreshold   float64
	trustedHamCount   int64
	subjectPassKey    []byte
	subjectPassPeriod time.Duration

	webhookURL string
	// webhookSecret, when set, HMAC-SHA256-signs outbound webhook payloads
	// (X-Octo-Mail-Signature) so receivers can verify authenticity. Empty = unsigned.
	webhookSecret []byte

	adminAddr  string
	adminToken string

	// egressPool: when true, outbound deliveries bind a per-tenant source IP
	// leased from the IPRouter (multi-egress warmup/reputation isolation).
	egressPool bool

	// sendRateMax / sendRateWindow configure the per-tenant outbound send-rate
	// limiter (deliverability.Service.AllowSend), enforced on every send regardless
	// of egressPool. sendRateMax is the max sends per tenant per window; 0 disables
	// the limiter (default). sendRateWindow is the fixed window (default 1m).
	sendRateMax    int64
	sendRateWindow time.Duration

	// ACME/autotls: when acmeDir URL is set, listeners use automatic certificates.
	// NOTE: the ACME cache is node-local, so this is single-node only — multi-node
	// deployments must terminate TLS at a shared proxy or provision certs
	// externally (see H17; leader-gated cluster issuance is a tracked follow-up).
	acmeDirectory string
	acmeContact   string
	acmeCacheDir  string
	acmeHosts     []dns.Domain
}

func loadConfig() config {
	return config{
		dsn:               envDefault("OCTO_MAIL_DSN", "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"),
		nodeID:            envDefault("OCTO_MAIL_NODE_ID", defaultNodeID()),
		hostname:          envDefault("OCTO_MAIL_HOSTNAME", "octo-mail.local"),
		bounceDomain:      envLower("OCTO_MAIL_BOUNCE_DOMAIN"),
		verpKey:           []byte(os.Getenv("OCTO_MAIL_VERP_KEY")),
		allowUnsignedVERP: os.Getenv("OCTO_MAIL_ALLOW_UNSIGNED_VERP") == "1",
		reporter:          os.Getenv("OCTO_MAIL_REPORTER") == "1",
		reportInterval:    envDuration("OCTO_MAIL_REPORT_INTERVAL", 6*time.Hour),
		reportDomain:      envLower("OCTO_MAIL_REPORT_DOMAIN"),
		maxSize:           envInt64("OCTO_MAIL_MAX_SIZE", 50*1024*1024),
		maxConns:          int(envInt64("OCTO_MAIL_MAX_CONNS", 1024)),
		drainTimeout:      envDuration("OCTO_MAIL_DRAIN_TIMEOUT", 30*time.Second),

		blobDir: envDefault("OCTO_MAIL_BLOB_DIR", "./blobs"),

		s3Endpoint:     os.Getenv("OCTO_MAIL_S3_ENDPOINT"),
		s3Region:       envDefault("OCTO_MAIL_S3_REGION", "us-east-1"),
		s3Bucket:       envDefault("OCTO_MAIL_S3_BUCKET", "octo-mail"),
		s3Access:       os.Getenv("OCTO_MAIL_S3_ACCESS"),
		s3Secret:       os.Getenv("OCTO_MAIL_S3_SECRET"),
		s3SessionToken: os.Getenv("OCTO_MAIL_S3_SESSION_TOKEN"),

		smtpAddr:       envDefault("OCTO_MAIL_SMTP_ADDR", ":25"),
		submissionAddr: envDefault("OCTO_MAIL_SUBMISSION_ADDR", ":587"),
		imapAddr:       envDefault("OCTO_MAIL_IMAP_ADDR", ":143"),
		jmapAddr:       envDefault("OCTO_MAIL_JMAP_ADDR", ":8080"),
		jmapBaseURL:    envDefault("OCTO_MAIL_JMAP_BASEURL", "http://localhost:8080"),

		queueInterval:    envDuration("OCTO_MAIL_QUEUE_INTERVAL", 5*time.Second),
		projInterval:     envDuration("OCTO_MAIL_PROJECTION_INTERVAL", 10*time.Second),
		queueBackoff:     envDuration("OCTO_MAIL_QUEUE_BACKOFF", 7*time.Minute+30*time.Second),
		queueMaxBackoff:  envDuration("OCTO_MAIL_QUEUE_MAX_BACKOFF", 4*time.Hour),
		queueMaxLifetime: envDuration("OCTO_MAIL_QUEUE_MAX_LIFETIME", 5*24*time.Hour),
		queueDelayDSN:    int(envInt64("OCTO_MAIL_QUEUE_DELAY_DSN", 5)),
		queueRetKeep:     envDuration("OCTO_MAIL_QUEUE_RETIRED_KEEP", 7*24*time.Hour),

		dnsblZones:  parseDomainList(os.Getenv("OCTO_MAIL_DNSBL_ZONES")),
		rejectDMARC: os.Getenv("OCTO_MAIL_REJECT_DMARC") == "1",
		maxHops:     int(envInt64("OCTO_MAIL_MAX_HOPS", 50)),
		greylist:    os.Getenv("OCTO_MAIL_GREYLIST") == "1",

		junkThreshold: envFloat("OCTO_MAIL_JUNK_THRESHOLD", 0.95),

		greylistDelay:     envDuration("OCTO_MAIL_GREYLIST_DELAY", 0),
		rejectThreshold:   envFloat("OCTO_MAIL_REJECT_THRESHOLD", 0),
		trustedHamCount:   envInt64("OCTO_MAIL_TRUSTED_HAM_COUNT", 0),
		subjectPassKey:    []byte(os.Getenv("OCTO_MAIL_SUBJECTPASS_KEY")),
		subjectPassPeriod: envDuration("OCTO_MAIL_SUBJECTPASS_PERIOD", 0),

		webhookURL:    os.Getenv("OCTO_MAIL_WEBHOOK_URL"),
		webhookSecret: []byte(os.Getenv("OCTO_MAIL_WEBHOOK_SECRET")),

		adminAddr:  envDefault("OCTO_MAIL_ADMIN_ADDR", ":8081"),
		adminToken: os.Getenv("OCTO_MAIL_ADMIN_TOKEN"),

		egressPool: os.Getenv("OCTO_MAIL_EGRESS_POOL") == "1",

		sendRateMax:    envInt64("OCTO_MAIL_SEND_RATE_MAX", 0),
		sendRateWindow: envDuration("OCTO_MAIL_SEND_RATE_WINDOW", time.Minute),

		acmeDirectory: os.Getenv("OCTO_MAIL_ACME_DIRECTORY"),
		acmeContact:   os.Getenv("OCTO_MAIL_ACME_CONTACT"),
		acmeCacheDir:  envDefault("OCTO_MAIL_ACME_CACHE", "./acme"),
		acmeHosts:     parseDomainList(os.Getenv("OCTO_MAIL_ACME_HOSTS")),
	}
}

func envFloat(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// parseDomainList parses a comma-separated list of DNS domains into []dns.Domain,
// skipping blanks and unparseable entries. Used for both DNSBL zones and ACME
// hostnames. Empty input yields an empty list.
func parseDomainList(s string) []dns.Domain {
	var out []dns.Domain
	for _, z := range strings.Split(s, ",") {
		z = strings.TrimSpace(z)
		if z == "" {
			continue
		}
		if d, err := dns.ParseDomain(z); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envLower reads an env var and returns it trimmed and lowercased — used for
// case-insensitive identifiers like a DNS domain read from operator config.
func envLower(k string) string {
	return strings.ToLower(strings.TrimSpace(os.Getenv(k)))
}

func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func defaultNodeID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h + "-" + strconv.Itoa(os.Getpid())
	}
	return "node-" + strconv.Itoa(os.Getpid())
}
