package main

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
)

// config is the node's runtime configuration, loaded from the environment.
type config struct {
	dsn      string
	nodeID   string
	hostname string
	maxSize  int64

	blobDir string // fs blob store dir (used when s3Endpoint is empty)

	s3Endpoint string
	s3Region   string
	s3Bucket   string
	s3Access   string
	s3Secret   string

	smtpAddr       string
	submissionAddr string
	imapAddr       string
	jmapAddr       string
	jmapBaseURL    string

	queueInterval time.Duration
	projInterval  time.Duration
	queueBackoff  time.Duration // base retry delay; doubles per attempt
	queueDelayDSN int           // attempts before a "still trying" warning DSN (0=off)
	queueRetKeep  time.Duration // how long to keep retired queue messages before cleanup

	dnsblZones  []dns.Domain
	rejectDMARC bool
	greylist    bool

	junkDir       string
	junkThreshold float64

	webhookURL string

	adminAddr  string
	adminToken string

	// egressPool: when true, outbound deliveries bind a per-tenant source IP
	// leased from the IPRouter (multi-egress warmup/reputation isolation).
	egressPool bool

	// ACME/autotls: when acmeDir URL is set, listeners use automatic certificates.
	acmeDirectory string
	acmeContact   string
	acmeCacheDir  string
	acmeHosts     []dns.Domain
}

func loadConfig() config {
	return config{
		dsn:      envDefault("OCTO_MAIL_DSN", "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"),
		nodeID:   envDefault("OCTO_MAIL_NODE_ID", defaultNodeID()),
		hostname: envDefault("OCTO_MAIL_HOSTNAME", "octo-mail.local"),
		maxSize:  envInt64("OCTO_MAIL_MAX_SIZE", 50*1024*1024),

		blobDir: envDefault("OCTO_MAIL_BLOB_DIR", "./blobs"),

		s3Endpoint: os.Getenv("OCTO_MAIL_S3_ENDPOINT"),
		s3Region:   envDefault("OCTO_MAIL_S3_REGION", "us-east-1"),
		s3Bucket:   envDefault("OCTO_MAIL_S3_BUCKET", "octo-mail"),
		s3Access:   os.Getenv("OCTO_MAIL_S3_ACCESS"),
		s3Secret:   os.Getenv("OCTO_MAIL_S3_SECRET"),

		smtpAddr:       envDefault("OCTO_MAIL_SMTP_ADDR", ":25"),
		submissionAddr: envDefault("OCTO_MAIL_SUBMISSION_ADDR", ":587"),
		imapAddr:       envDefault("OCTO_MAIL_IMAP_ADDR", ":143"),
		jmapAddr:       envDefault("OCTO_MAIL_JMAP_ADDR", ":8080"),
		jmapBaseURL:    envDefault("OCTO_MAIL_JMAP_BASEURL", "http://localhost:8080"),

		queueInterval: envDuration("OCTO_MAIL_QUEUE_INTERVAL", 5*time.Second),
		projInterval:  envDuration("OCTO_MAIL_PROJECTION_INTERVAL", 10*time.Second),
		queueBackoff:  envDuration("OCTO_MAIL_QUEUE_BACKOFF", 7*time.Minute+30*time.Second),
		queueDelayDSN: int(envInt64("OCTO_MAIL_QUEUE_DELAY_DSN", 5)),
		queueRetKeep:  envDuration("OCTO_MAIL_QUEUE_RETIRED_KEEP", 7*24*time.Hour),

		dnsblZones:  parseDomainList(os.Getenv("OCTO_MAIL_DNSBL_ZONES")),
		rejectDMARC: os.Getenv("OCTO_MAIL_REJECT_DMARC") == "1",
		greylist:    os.Getenv("OCTO_MAIL_GREYLIST") == "1",

		junkDir:       envDefault("OCTO_MAIL_JUNK_DIR", "./junk"),
		junkThreshold: envFloat("OCTO_MAIL_JUNK_THRESHOLD", 0.95),

		webhookURL: os.Getenv("OCTO_MAIL_WEBHOOK_URL"),

		adminAddr:  envDefault("OCTO_MAIL_ADMIN_ADDR", ":8081"),
		adminToken: os.Getenv("OCTO_MAIL_ADMIN_TOKEN"),

		egressPool: os.Getenv("OCTO_MAIL_EGRESS_POOL") == "1",

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
