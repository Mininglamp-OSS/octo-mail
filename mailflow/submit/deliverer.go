package submit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/Mininglamp-OSS/octo-mail/core/addr"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/ops/obs"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtpclient"
)

// Dialer opens a connection to the MX for a recipient domain. Production dials
// the MX host over TCP (after DNS MX lookup); tests inject a fake endpoint. It
// returns the conn plus the remote hostname (for EHLO/TLS).
type Dialer func(ctx context.Context, domain string) (net.Conn, dns.Domain, error)

// tenantCtxKey carries the delivering tenant id through the dial context so a
// tenant-aware SourceIPDialer (multi-egress IP-pool routing) can lease a source
// IP for that tenant without widening the Dialer signature.
type tenantCtxKey struct{}

// WithTenant returns ctx annotated with the delivering tenant id; a SourceIPDialer
// pickSource reads it via TenantFrom to lease the tenant's egress IP.
func WithTenant(ctx context.Context, tenantID int64) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenantID)
}

// TenantFrom returns the tenant id set by WithTenant, or 0 if absent.
func TenantFrom(ctx context.Context) int64 {
	if v, ok := ctx.Value(tenantCtxKey{}).(int64); ok {
		return v
	}
	return 0
}

// SMTPDeliverer builds a queue.Deliverer that reads the message body from the
// blob store and delivers it to the recipient's MX via the smtpclient — a real
// SMTP session. TLS mode is opportunistic in production; tests use skip over an
// in-memory pipe.
type SMTPDeliverer struct {
	Blob         blob.Store
	Dial         Dialer
	EHLOHostname dns.Domain
	TLSMode      smtpclient.TLSMode
	Log          *slog.Logger

	// Gate, if set, is the per-tenant reputation send gate: it is consulted with
	// (tenantID, remoteDomain) before each delivery. Returning a non-nil error
	// blocks the send (e.g. this tenant is paused for this domain), isolating one
	// spammy tenant from the platform. Injected as a func to avoid coupling the
	// submit package to deliverability.
	Gate func(ctx context.Context, tenantID int64, remoteDomain string) error

	// Sign, if set, returns DKIM-Signature header line(s) for (tenantID,
	// fromDomain, rawMessage), prepended to the body before delivery so the
	// signature — and thus reputation — accrues to the tenant's own domain.
	// Returns "" to send unsigned.
	Sign func(ctx context.Context, tenantID int64, fromDomain string, msg []byte) (string, error)

	// RecordSent, if set, records a successful send for reputation accounting.
	RecordSent func(ctx context.Context, tenantID int64, remoteDomain string) error

	// EnvelopeFrom, if set, computes the SMTP envelope MAIL FROM for a message —
	// used for VERP: return bounces+<tenant>.<msg>@<bounceDomain> so bounces and
	// FBL complaints route back to the exact sending tenant. The visible From
	// header and DKIM signature are unchanged (DKIM keeps DMARC aligned via the
	// tenant's own domain; SPF aligns on the bounce domain the operator publishes).
	// Returning "" falls back to m.MailFrom. nil disables VERP entirely.
	EnvelopeFrom func(m queue.Msg) string

	// Suppressed, if set, is checked before each send; returning true blocks the
	// send (recipient is on the account's suppression list) — the message is
	// retired as a permanent failure without dialing.
	Suppressed func(ctx context.Context, accountID int64, rcptTo string) (bool, error)

	// OnDelivered / OnFailed, if set, emit webhook events (best-effort) after a
	// successful delivery or a send attempt error, respectively.
	OnDelivered func(ctx context.Context, m queue.Msg)
	OnSendError func(ctx context.Context, m queue.Msg, err error)

	// TLSModeFor, if set, resolves the outbound TLS mode per recipient domain
	// (e.g. MTA-STS enforce → required STARTTLS). Overrides TLSMode when it
	// returns a non-empty mode.
	TLSModeFor func(ctx context.Context, domain string) (smtpclient.TLSMode, error)

	// DANEFor, if set, resolves DNSSEC-authenticated TLSA records for the MX host
	// of a recipient domain (via the smtpclient.GatherTLSA over a DNSSEC-aware
	// resolver). When it returns a non-empty record set, delivery is upgraded to
	// required STARTTLS and the peer certificate is verified against those TLSA
	// records — DANE. moreHostnames are additional certificate names allowed for
	// DANE-TA. Returning an empty set means the domain has no DANE policy (fall
	// back to the configured/MTA-STS TLS mode). Injected as a func to avoid
	// coupling submit to the DNS resolver wiring.
	DANEFor func(ctx context.Context, domain string, mx dns.Domain) (records []adns.TLSA, moreHostnames []dns.Domain, err error)
}

// ErrSuppressed indicates the recipient is on the account suppression list.
var ErrSuppressed = errors.New("recipient suppressed")

// Deliver implements queue.Deliverer.
func (d *SMTPDeliverer) Deliver(ctx context.Context, m queue.Msg) error {
	domain := addr.Domain(m.RcptTo)
	if domain == "" {
		return fmt.Errorf("bad recipient %q", m.RcptTo)
	}

	// Suppression list: never send to a hard-bounced/complained recipient. Fail
	// closed — a lookup error defers the send rather than risking delivery to a
	// suppressed address (which would harm sender reputation).
	if d.Suppressed != nil {
		sup, err := d.Suppressed(ctx, m.AccountID, m.RcptTo)
		if err != nil {
			return fmt.Errorf("suppression check for %s: %w", m.RcptTo, err)
		}
		if sup {
			return fmt.Errorf("%w: %s", ErrSuppressed, m.RcptTo)
		}
	}

	// Reputation gate: block the send if this tenant is throttled for this
	// remote domain. Structural per-tenant isolation — another tenant is
	// unaffected.
	if d.Gate != nil {
		if err := d.Gate(ctx, m.TenantID, domain); err != nil {
			return fmt.Errorf("send gate: %w", err)
		}
	}

	// Read the body from the blob store.
	br, err := d.Blob.Open(ctx, m.TenantID, blob.Ref(m.BlobRef))
	if err != nil {
		return fmt.Errorf("open body: %w", err)
	}
	defer br.Close()

	// Assemble the outbound message, DKIM-signing with the tenant key if enabled.
	var bodyReader io.Reader = br
	bodySize := br.Size()
	if d.Sign != nil {
		raw, err := io.ReadAll(br)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		// DKIM d= must align with the From: header domain for DMARC (RFC 6376/7489),
		// not the envelope MAIL FROM — they differ for auto-replies (null return
		// path) and any bounce/DSN. Prefer the From-header domain; fall back to the
		// envelope only when the header is unparseable.
		fromDomain := fromHeaderDomain(raw)
		if fromDomain == "" {
			fromDomain = addr.Domain(m.MailFrom)
		}
		header, err := d.Sign(ctx, m.TenantID, fromDomain, raw)
		if err != nil {
			return fmt.Errorf("dkim sign: %w", err)
		}
		signed := append([]byte(header), raw...)
		bodyReader = bytes.NewReader(signed)
		bodySize = int64(len(signed))
	}

	conn, remote, err := d.Dial(WithTenant(ctx, m.TenantID), domain)
	if err != nil {
		return fmt.Errorf("dial mx for %s: %w", domain, err)
	}
	defer conn.Close()

	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	tlsMode := d.TLSMode
	if tlsMode == "" {
		tlsMode = smtpclient.TLSOpportunistic
	}
	// MTA-STS-aware TLS mode override (e.g. enforce → required STARTTLS).
	if d.TLSModeFor != nil {
		if mode, err := d.TLSModeFor(ctx, domain); err == nil && mode != "" {
			tlsMode = mode
		}
	}
	// DANE: if the MX host publishes DNSSEC-authenticated TLSA records, require
	// STARTTLS and verify the peer certificate against them. DANE takes
	// precedence over opportunistic TLS — a downgrade would defeat it.
	var opts smtpclient.Opts
	if d.DANEFor != nil {
		records, moreHosts, err := d.DANEFor(ctx, domain, remote)
		if err != nil {
			if d.OnSendError != nil {
				d.OnSendError(ctx, m, err)
			}
			return fmt.Errorf("dane lookup for %s: %w", domain, err)
		}
		if len(records) > 0 {
			if tlsMode == smtpclient.TLSOpportunistic || tlsMode == smtpclient.TLSSkip {
				tlsMode = smtpclient.TLSRequiredStartTLS
			}
			opts.DANERecords = records
			opts.DANEMoreHostnames = moreHosts
		}
	}
	// Per-message RequireTLS override (RFC 8689 REQUIRETLS / TLS-Required header),
	// applied last so it wins over the domain policy: true forces verified STARTTLS
	// (never downgrade); false permits plaintext even where a policy would require
	// TLS (operator override for a broken peer). nil leaves the resolved mode.
	if m.RequireTLS != nil {
		if *m.RequireTLS {
			tlsMode = smtpclient.TLSRequiredStartTLS
		} else {
			tlsMode = smtpclient.TLSOpportunistic
			opts.DANERecords = nil
			opts.DANEMoreHostnames = nil
		}
	}
	cl, err := smtpclient.New(ctx, log, conn, tlsMode, false, d.EHLOHostname, remote, opts)
	if err != nil {
		if d.OnSendError != nil {
			d.OnSendError(ctx, m, err)
		}
		return fmt.Errorf("smtp client to %s: %w", domain, err)
	}
	defer cl.Close()

	// Envelope MAIL FROM: VERP bounce address when configured, else the original
	// sender. Only the transmitted envelope changes — m.MailFrom (retained in the
	// queue row) still drives DSN/records.
	envFrom := m.MailFrom
	if d.EnvelopeFrom != nil {
		if v := d.EnvelopeFrom(m); v != "" {
			envFrom = v
		}
	}
	if err := cl.Deliver(ctx, envFrom, m.RcptTo, bodySize, bodyReader, m.Body8BitMIME, m.SMTPUTF8, false); err != nil {
		if d.OnSendError != nil {
			d.OnSendError(ctx, m, err)
		}
		obs.OutboundSent.WithLabelValues("error").Inc()
		return smtpResultErr(fmt.Errorf("smtp deliver to %s: %w", m.RcptTo, err), err)
	}

	if d.RecordSent != nil {
		if err := d.RecordSent(ctx, m.TenantID, domain); err != nil {
			// Non-fatal: the message was delivered; reputation accounting is
			// best-effort.
			log.WarnContext(ctx, "record sent for reputation failed", "err", err)
		}
	}
	if d.OnDelivered != nil {
		d.OnDelivered(ctx, m)
	}
	obs.OutboundSent.WithLabelValues("ok").Inc()
	return nil
}

// resultErr wraps a delivery error with SMTP result detail so the queue's
// per-attempt results history can record the reply code + enhanced status, and so
// the worker can distinguish a permanent (5xx) failure from a transient one. It
// satisfies queue.ResultError and queue.PermanentError.
type resultErr struct {
	err       error
	code      int
	secode    string
	permanent bool
}

func (e *resultErr) Error() string             { return e.err.Error() }
func (e *resultErr) Unwrap() error             { return e.err }
func (e *resultErr) SMTPResult() (int, string) { return e.code, e.secode }
func (e *resultErr) Permanent() bool           { return e.permanent }

// smtpResultErr builds a resultErr from the smtpclient error (if it is one),
// extracting the code/secode and permanence; otherwise it records code 0 and
// treats the error as transient (retryable).
func smtpResultErr(wrapped, cause error) error {
	var se *smtpclient.Error
	if errors.As(cause, &se) {
		return &resultErr{err: wrapped, code: se.Code, secode: se.Secode, permanent: se.Permanent}
	}
	return wrapped
}

// fromHeaderDomain returns the domain of the message's From: header (the DKIM/
// DMARC alignment identity), or "" if it can't be parsed. Uses mox's canonical
// RFC 5322 parser, matching the inbound authentication path.
func fromHeaderDomain(raw []byte) string {
	a, _, _, err := message.From(nil, false, byteReaderAt(raw), nil)
	if err != nil {
		return ""
	}
	return a.Domain.ASCII
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
