// Package smtpd is a compact, real SMTP receiving server bound to the octo-mail
// kernel. It speaks enough of RFC 5321 for a real client (the smtpclient,
// unmodified) to deliver a message: EHLO, MAIL FROM, RCPT TO, DATA, QUIT, RSET.
// Each accepted message is resolved through the directory (structural tenant
// isolation) and appended to the recipient account's change-log — the same
// InboundTarget.Deliver path the kernel test exercised, now driven by real SMTP.
//
// It reuses the smtp package for address parsing, reply/status codes and the
// dot-unstuffing DataReader; the command loop is our own.
package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/ops/obs"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
)

// Server receives mail and delivers into the kernel via the directory.
type Server struct {
	Dir      directory.Directory
	Hostname string // announced in greeting/EHLO
	// MaxSize bounds accepted message size (0 = unlimited).
	MaxSize int64
	// MaxRcpt caps recipients per message, advertised via LIMITS RCPTMAX (RFC
	// 9422) and enforced in RCPT. 0 uses defaultMaxRcpt.
	MaxRcpt int

	// Submission, if set, puts this listener in submission mode (port 587): it
	// requires AUTH, accepts any recipient, and enqueues the message to the
	// shared outbound queue via Submit instead of delivering locally. When nil,
	// the listener is an MX receiver (port 25): no auth, recipients must resolve
	// to local accounts, messages append to their change-logs.
	Submission *submit.Submitter

	// TLSConfig, when set, advertises STARTTLS. In submission mode it also makes
	// TLS mandatory before AUTH — the password never crosses the wire in the
	// clear (mirrors imapd). When nil, the listener is plaintext-only.
	TLSConfig *tls.Config

	// Auth, when set (MX receive mode only), authenticates each received message
	// — SPF/DKIM/DMARC/iprev/DNSBL — and prepends a Received + Authentication-
	// Results header prefix (stored in the DB, not the blob). When nil, messages
	// are accepted without authentication (dev/trusted-boundary only).
	Auth *inbound.Authenticator

	// RejectDMARCFail, when true, rejects messages whose DMARC result says reject
	// (aligned failure under a p=reject/quarantine policy). When false, the
	// message is still accepted and the failure is recorded in the header for the
	// junk filter / account rules to act on.
	RejectDMARCFail bool

	// Junk, when set, classifies each accepted message per recipient account; a
	// message classified as spam is delivered to the account's "Junk" mailbox
	// instead of "Inbox". Injected as an interface to avoid an import cycle.
	Junk JunkClassifier

	// Decider, when set, makes the inbound accept/defer/reject decision
	// (greylist + reputation + bayesian content) after DATA — the the analyze
	// equivalent. When set it supersedes the plain Junk-only routing.
	Decider *inbound.Decider

	// DMARCRecorder, when set, accumulates each authenticated message's DMARC
	// evaluation for later aggregate-report generation (P0-3). Injected as a func
	// to avoid coupling smtpd to reportdb.
	DMARCRecorder func(ctx context.Context, fromDomain, sourceIP, spf, dkim, disposition string)

	// VacationResponder, when set, is invoked after a message is delivered to a
	// recipient account's Inbox. It sends a JMAP vacation auto-reply if the
	// account has one enabled and this sender has not been replied to recently.
	// Injected as a func to avoid coupling smtpd to the vacation store/queue.
	VacationResponder func(ctx context.Context, accountID int64, sender, recipient string, raw []byte)

	// BURLResolver, when set (submission mode), resolves an RFC 4467 authorized
	// IMAP URL to message bytes for the BURL command (RFC 4468), so a client can
	// submit a message it composed in IMAP without downloading it. It is called
	// with the authenticated account id; ok is false on any validation failure.
	// Injected as a func to avoid coupling smtpd to imapd/store URLAUTH logic.
	BURLResolver func(ctx context.Context, accountID int64, authURL string) (data []byte, ok bool)

	// BounceDomain, when set, is the VERP bounce/FBL domain. Inbound mail whose
	// recipient domain equals it is routed to BounceHandler instead of normal
	// mailbox delivery (it belongs to no account). Lowercase.
	BounceDomain string

	// BounceHandler, when set, processes a message delivered to BounceDomain: an
	// ARF complaint or a DSN bounce addressed to a VERP recipient. verpLocalpart
	// is the recipient localpart (the VERP token). It records the reputation
	// event + suppresses the recipient. Errors are logged, never bounced (a bounce
	// of a bounce would loop). Injected to avoid coupling smtpd to deliverability.
	BounceHandler func(ctx context.Context, verpLocalpart string, raw []byte)
}

// JunkClassifier classifies a raw message for an account as spam or not.
type JunkClassifier interface {
	Classify(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error)
}

// defaultMaxRcpt is the RCPT-per-message cap used when Server.MaxRcpt is unset.
const defaultMaxRcpt = 1000

// maxFutureRelease bounds the FUTURERELEASE (RFC 4865) hold interval: a client
// may defer delivery up to this far in the future.
const maxFutureRelease = 90 * 24 * time.Hour

// maxRcpt returns the effective per-message recipient limit (LIMITS RCPTMAX).
func (s *Server) maxRcpt() int {
	if s.MaxRcpt > 0 {
		return s.MaxRcpt
	}
	return defaultMaxRcpt
}

// Serve handles one connection until QUIT/close.
func (s *Server) Serve(ctx context.Context, nc net.Conn) error {
	host := s.Hostname
	if host == "" {
		host = "octo-mail.local"
	}
	c := &conn{srv: s, ctx: ctx, host: host, nc: nc,
		br: bufio.NewReader(nc), bw: bufio.NewWriter(nc)}
	return c.serve()
}

type conn struct {
	srv  *Server
	ctx  context.Context
	host string
	nc   net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	tls  bool // connection is encrypted (after STARTTLS)

	mailFrom  string
	haveFrom  bool
	rcpts     []directory.InboundTarget
	rcptAddrs []string
	helo      string // EHLO/HELO domain argument

	// DSN request parameters (RFC 3461): RET (FULL/HDRS) and ENVID on MAIL;
	// NOTIFY and ORCPT on RCPT (parallel to subRcpts, per recipient).
	dsnRet    string
	dsnEnvID  string
	subNotify []string
	subORcpt  []string

	// holdUntil is the FUTURERELEASE (RFC 4865) release time from MAIL FROM
	// HOLDFOR/HOLDUNTIL; zero means deliver immediately.
	holdUntil time.Time

	// bdatBuf accumulates BDAT chunks (RFC 3030 CHUNKING) until BDAT LAST.
	bdatBuf []byte
	inBDAT  bool

	// submission mode: authenticated sender's tenant/account, and plain recipient
	// addresses (not resolved to local targets).
	authed      bool
	authTenant  int64
	authAccount int64
	authScope   directory.TenantScope // authenticated scope, for MAIL FROM ownership checks
	subRcpts    []string
	// bounceRcpts holds VERP recipient localparts for mail addressed to the
	// bounce domain (ARF/DSN), routed to the bounce handler instead of a mailbox.
	bounceRcpts []string
}

func (c *conn) writef(format string, a ...any) error {
	if _, err := fmt.Fprintf(c.bw, format+"\r\n", a...); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *conn) serve() error {
	if err := c.writef("220 %s ESMTP octo-mail", c.host); err != nil {
		return err
	}
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		cmd, rest := splitCmd(line)
		switch strings.ToUpper(cmd) {
		case "EHLO":
			c.helo = strings.TrimSpace(rest)
			// Multi-line 250. Offer STARTTLS if configured; offer AUTH only over
			// an encrypted channel in submission mode.
			if err := c.writef("250-%s greets you", c.host); err != nil {
				return err
			}
			if c.srv.TLSConfig != nil && !c.tls {
				if err := c.writef("250-STARTTLS"); err != nil {
					return err
				}
			}
			if c.srv.Submission != nil && c.authAllowed() {
				// SCRAM (password never on the wire) is offered when the directory
				// supports it; the channel-binding -PLUS variant only over TLS.
				mechs := "PLAIN"
				if _, ok := c.srv.Dir.(directory.SCRAMAuthenticator); ok {
					mechs += " SCRAM-SHA-256"
					if c.tls {
						mechs += " SCRAM-SHA-256-PLUS"
					}
				}
				if err := c.writef("250-AUTH %s", mechs); err != nil {
					return err
				}
			}
			// FUTURERELEASE (RFC 4865): submission clients may defer delivery via
			// MAIL FROM HOLDFOR/HOLDUNTIL, up to maxFutureRelease.
			if c.srv.Submission != nil {
				if err := c.writef("250-FUTURERELEASE %d %s", int(maxFutureRelease/time.Second), time.Now().Add(maxFutureRelease).UTC().Format("2006-01-02T15:04:05Z")); err != nil {
					return err
				}
			}
			if err := c.writef("250-PIPELINING"); err != nil {
				return err
			}
			// SIZE: advertise the max message size (0 = no explicit limit; still
			// advertise the keyword so clients know SIZE is supported).
			if c.srv.MaxSize > 0 {
				if err := c.writef("250-SIZE %d", c.srv.MaxSize); err != nil {
					return err
				}
			} else {
				if err := c.writef("250-SIZE 0"); err != nil {
					return err
				}
			}
			if err := c.writef("250-8BITMIME"); err != nil {
				return err
			}
			if err := c.writef("250-ENHANCEDSTATUSCODES"); err != nil {
				return err
			}
			if err := c.writef("250-LIMITS RCPTMAX=%d", c.srv.maxRcpt()); err != nil {
				return err
			}
			if err := c.writef("250-DSN"); err != nil {
				return err
			}
			if err := c.writef("250-CHUNKING"); err != nil {
				return err
			}
			if c.tls {
				if err := c.writef("250-REQUIRETLS"); err != nil {
					return err
				}
			}
			// BURL (RFC 4468): submission-side consumer of URLAUTH. Advertised only
			// when submission is configured with a resolver. "imap" = the trusted
			// same-server source we resolve.
			if c.srv.Submission != nil && c.srv.BURLResolver != nil {
				if err := c.writef("250-BURL imap"); err != nil {
					return err
				}
			}
			if err := c.writef("250 SMTPUTF8"); err != nil {
				return err
			}
		case "HELO":
			c.helo = strings.TrimSpace(rest)
			if err := c.writef("250 %s", c.host); err != nil {
				return err
			}
		case "STARTTLS":
			if err := c.cmdStartTLS(); err != nil {
				return err
			}
		case "AUTH":
			c.cmdAuth(rest)
		case "MAIL":
			c.cmdMail(rest)
		case "RCPT":
			c.cmdRcpt(rest)
		case "DATA":
			if err := c.cmdData(); err != nil {
				return err
			}
		case "BDAT":
			if err := c.cmdBDAT(rest); err != nil {
				return err
			}
		case "BURL":
			if err := c.cmdBURL(rest); err != nil {
				return err
			}
		case "RSET":
			c.reset()
			c.writef("250 2.0.0 OK")
		case "NOOP":
			c.writef("250 2.0.0 OK")
		case "VRFY":
			// RFC 5321 §3.5.3: we don't confirm addresses (avoids leaking valid
			// recipients to probes) but will accept mail — reply 252.
			c.writef("252 2.5.2 cannot VRFY user, but will accept message")
		case "EXPN":
			c.writef("502 5.5.1 EXPN not supported")
		case "HELP":
			c.writef("214 2.0.0 octo-mail ESMTP; see RFC 5321")
		case "QUIT":
			c.writef("221 2.0.0 %s closing", c.host)
			return nil
		default:
			c.writef("%d 5.5.1 command not recognized", smtp.C500BadSyntax)
		}
	}
}

func (c *conn) reset() {
	c.mailFrom, c.haveFrom = "", false
	c.rcpts = nil
	c.rcptAddrs = nil
	c.subRcpts = nil
	c.bounceRcpts = nil
	c.subNotify = nil
	c.subORcpt = nil
	c.dsnRet = ""
	c.dsnEnvID = ""
	c.holdUntil = time.Time{}
	c.bdatBuf = nil
	c.inBDAT = false
}

// authAllowed reports whether AUTH may be offered/accepted now: always over TLS,
// and (for dev/tests) when no TLS is configured at all. When TLS is configured
// but not yet active, AUTH is withheld so the password cannot cross in clear.
func (c *conn) authAllowed() bool {
	return c.tls || c.srv.TLSConfig == nil
}

// cmdStartTLS upgrades the connection to TLS in place (RFC 3207).
func (c *conn) cmdStartTLS() error {
	if c.srv.TLSConfig == nil {
		return c.writef("%d 5.5.1 STARTTLS not available", smtp.C502CmdNotImpl)
	}
	if c.tls {
		return c.writef("%d 5.5.1 already using TLS", smtp.C503BadCmdSeq)
	}
	if err := c.writef("%d 2.0.0 ready to start TLS", smtp.C220ServiceReady); err != nil {
		return err
	}
	tc := tls.Server(c.nc, c.srv.TLSConfig)
	if err := tc.Handshake(); err != nil {
		return err
	}
	c.nc = tc
	c.br = bufio.NewReader(tc)
	c.bw = bufio.NewWriter(tc)
	c.tls = true
	// RFC 3207: discard any state learned before TLS.
	c.reset()
	c.authed = false
	return nil
}

// cmdAuth handles AUTH PLAIN in submission mode. Credential VERIFICATION is
// hardened in WF2; here it resolves the login to a tenant/account via the
// directory so submission can attribute the outbound message. Rejected outside
// submission mode.
func (c *conn) cmdAuth(rest string) {
	if c.srv.Submission == nil {
		c.writef("%d 5.5.1 AUTH not available", smtp.C503BadCmdSeq)
		return
	}
	if !c.authAllowed() {
		c.writef("%d 5.7.11 must issue STARTTLS before AUTH", smtp.C538EncReqForAuth)
		return
	}
	mech, arg := splitCmd(strings.TrimSpace(rest))
	switch {
	case strings.EqualFold(mech, "PLAIN"):
		c.authPlain(arg)
	case strings.EqualFold(mech, "SCRAM-SHA-256"):
		c.authSCRAM(arg, false)
	case strings.EqualFold(mech, "SCRAM-SHA-256-PLUS"):
		c.authSCRAM(arg, true)
	default:
		c.writef("%d 5.5.4 unsupported SASL mechanism", smtp.C504ParamNotImpl)
	}
}

// authPlain runs AUTH PLAIN (credential sent, verified against the directory).
func (c *conn) authPlain(arg string) {
	if arg == "" {
		c.writef("%d 5.5.4 AUTH PLAIN needs an initial response", smtp.C501BadParamSyntax)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		c.writef("%d 5.5.2 bad base64", smtp.C501BadParamSyntax)
		return
	}
	// SASL PLAIN: [authzid] NUL authcid NUL passwd
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		c.writef("%d 5.5.2 malformed PLAIN", smtp.C501BadParamSyntax)
		return
	}
	login := parts[1]
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	scope, _, err := c.srv.Dir.AuthenticatePrincipal(c.ctx, login, directory.PasswordCredential(parts[2]))
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	acc, err := scope.AccountForAddress(c.ctx, addr.Path())
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	c.authed = true
	c.authTenant = scope.Tenant().ID
	c.authAccount = acc.ID()
	c.authScope = scope
	c.reset() // discard any pre-auth transaction so a spoofed MAIL FROM can't survive AUTH
	c.writef("235 2.7.0 authenticated")
}

// authSCRAM runs AUTH SCRAM-SHA-256 or its channel-binding -PLUS variant (RFC
// 4954 SASL over SMTP + RFC 5802 SCRAM): the password proof is exchanged over
// 334 continuations so the secret never crosses the wire; -PLUS binds the proof
// to the TLS channel.
func (c *conn) authSCRAM(ir string, plus bool) {
	sa, ok := c.srv.Dir.(directory.SCRAMAuthenticator)
	if !ok {
		c.writef("%d 5.5.4 SCRAM not available", smtp.C504ParamNotImpl)
		return
	}
	var cs *tls.ConnectionState
	if plus {
		tc, ok := c.nc.(*tls.Conn)
		if !ok {
			c.writef("%d 5.7.11 SCRAM-SHA-256-PLUS requires TLS", smtp.C538EncReqForAuth)
			return
		}
		st := tc.ConnectionState()
		cs = &st
	}

	// Initial client response: inline, "=" for empty, or requested via a 334.
	clientFirst, ok := c.saslInitial(ir)
	if !ok {
		return
	}
	srv, err := scram.NewServer(sha256.New, clientFirst, cs, plus)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	login := srv.Authentication
	ver, err := sa.LookupSCRAM(c.ctx, login)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	serverFirst, err := srv.ServerFirst(ver.Iterations, ver.Salt)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	clientFinal, ok := c.saslChallenge([]byte(serverFirst))
	if !ok {
		return
	}
	serverFinal, err := srv.Finish(clientFinal, ver.SaltedPassword)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	// Deliver server-final in a 334, client acknowledges with an empty line.
	if _, ok := c.saslChallenge([]byte(serverFinal)); !ok {
		return
	}

	addr, err := smtp.ParseAddress(login)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	scope, _, err := sa.ScopeForLogin(c.ctx, login)
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	acc, err := scope.AccountForAddress(c.ctx, addr.Path())
	if err != nil {
		c.writef("%d 5.7.8 authentication failed", 535)
		return
	}
	c.authed = true
	c.authTenant = scope.Tenant().ID
	c.authAccount = acc.ID()
	c.authScope = scope
	c.reset() // discard any pre-auth transaction so a spoofed MAIL FROM can't survive AUTH
	c.writef("235 2.7.0 authenticated")
}

// saslInitial resolves the SASL initial response: inline base64, "=" for an
// empty response, or a 334 prompt. Returns the decoded bytes.
func (c *conn) saslInitial(ir string) ([]byte, bool) {
	if ir == "=" {
		return []byte{}, true
	}
	if ir != "" {
		b, err := base64.StdEncoding.DecodeString(ir)
		if err != nil {
			c.writef("%d 5.5.2 bad base64", smtp.C501BadParamSyntax)
			return nil, false
		}
		return b, true
	}
	return c.saslChallenge(nil)
}

// saslChallenge writes a 334 continuation carrying data (base64) and reads the
// client's base64 response line. A "*" cancels the exchange.
func (c *conn) saslChallenge(data []byte) ([]byte, bool) {
	c.writef("%d %s", smtp.C334ContinueAuth, base64.StdEncoding.EncodeToString(data))
	line, err := c.br.ReadString('\n')
	if err != nil {
		return nil, false
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "*" {
		c.writef("%d 5.7.8 authentication cancelled", 501)
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		c.writef("%d 5.5.2 bad base64", smtp.C501BadParamSyntax)
		return nil, false
	}
	return b, true
}

// senderOwned reports whether the given MAIL FROM address belongs to the
// authenticated account. It resolves the address through the authenticated
// tenant scope and compares the account id, so a submission client cannot send
// as an address it does not own.
func (c *conn) senderOwned(mailFrom string) bool {
	if c.authScope == nil {
		return false
	}
	addr, err := smtp.ParseAddress(mailFrom)
	if err != nil {
		return false
	}
	owner, err := c.authScope.AccountForAddress(c.ctx, addr.Path())
	if err != nil {
		return false
	}
	return owner.ID() == c.authAccount
}

func (c *conn) cmdMail(rest string) {
	addr, ok := parseAddrParam(rest, "FROM:")
	if !ok {
		c.writef("%d 5.5.4 bad MAIL syntax", smtp.C501BadParamSyntax)
		return
	}
	// SIZE= extension (RFC 1870): reject early if the declared size exceeds the
	// server limit, before accepting DATA.
	if sz, ok := mailParamInt(rest, "SIZE"); ok && c.srv.MaxSize > 0 && sz > c.srv.MaxSize {
		c.writef("552 5.3.4 message size %d exceeds limit %d", sz, c.srv.MaxSize)
		return
	}
	c.reset()
	c.mailFrom = addr
	c.haveFrom = true
	// Submission authz. In submission mode the sender must be authenticated
	// FIRST, and may then only use a MAIL FROM address that belongs to its own
	// account — otherwise any account could spoof any sender on the server's
	// IP/DKIM reputation. Rejecting MAIL before AUTH also closes the sequencing
	// bypass where MAIL FROM:<foreign> is sent pre-auth and the transaction
	// survives a later AUTH. Inbound MX traffic (Submission==nil, never authed)
	// legitimately carries arbitrary senders and is unaffected. A null return
	// path ("<>") is not a valid submission sender.
	if c.srv.Submission != nil {
		if !c.authed {
			c.mailFrom, c.haveFrom = "", false
			c.writef("%d 5.7.1 authentication required before MAIL", 530)
			return
		}
		if addr == "" || !c.senderOwned(addr) {
			c.mailFrom, c.haveFrom = "", false
			c.writef("550 5.7.1 sender %q is not an address of the authenticated account", addr)
			return
		}
	}
	// Capture DSN request parameters (RFC 3461): RET=FULL|HDRS, ENVID=<id>.
	c.dsnRet = mailParamStr(rest, "RET")
	c.dsnEnvID = mailParamStr(rest, "ENVID")
	// FUTURERELEASE (RFC 4865): HOLDFOR=<seconds> or HOLDUNTIL=<date-time> defers
	// delivery. Only in submission mode; the two are mutually exclusive and bound
	// to maxFutureRelease.
	if c.srv.Submission != nil {
		hf, hasHF := mailParamInt(rest, "HOLDFOR")
		hu := mailParamStr(rest, "HOLDUNTIL")
		switch {
		case hasHF && hu != "":
			c.reset()
			c.writef("%d 5.5.4 HOLDFOR and HOLDUNTIL are mutually exclusive", smtp.C501BadParamSyntax)
			return
		case hasHF:
			if hf < 0 || time.Duration(hf)*time.Second > maxFutureRelease {
				c.reset()
				c.writef("%d 5.5.4 HOLDFOR out of range", smtp.C501BadParamSyntax)
				return
			}
			c.holdUntil = time.Now().Add(time.Duration(hf) * time.Second)
		case hu != "":
			t, err := time.Parse(time.RFC3339, hu)
			if err != nil {
				c.reset()
				c.writef("%d 5.5.4 bad HOLDUNTIL date-time", smtp.C501BadParamSyntax)
				return
			}
			if t.After(time.Now().Add(maxFutureRelease)) {
				c.reset()
				c.writef("%d 5.5.4 HOLDUNTIL out of range", smtp.C501BadParamSyntax)
				return
			}
			c.holdUntil = t
		}
	}
	c.writef("%d 2.1.0 OK", smtp.C250Completed)
}

// mailParamStr extracts a string ESMTP parameter like "RET=FULL" from a
// MAIL/RCPT parameter string (case-insensitive key). Parameters are matched per
// whitespace-separated token, so a "KEY=" appearing inside the address or
// another value is never mistaken for the parameter.
func mailParamStr(rest, key string) string {
	pfx := strings.ToUpper(key) + "="
	for _, tok := range strings.Fields(rest) {
		if strings.HasPrefix(strings.ToUpper(tok), pfx) {
			return tok[len(pfx):]
		}
	}
	return ""
}

// hasDSNPerRcpt reports whether any per-recipient DSN param slot is non-empty, so
// the maps are only built when a client actually sent NOTIFY/ORCPT.
func hasDSNPerRcpt(vals []string) bool {
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}

// mailParamInt extracts an integer ESMTP parameter like "SIZE=12345" from a
// MAIL/RCPT parameter string (case-insensitive key).
func mailParamInt(rest, key string) (int64, bool) {
	v := mailParamStr(rest, key)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (c *conn) cmdRcpt(rest string) {
	if !c.haveFrom {
		c.writef("%d 5.5.1 need MAIL first", smtp.C503BadCmdSeq)
		return
	}
	addrStr, ok := parseAddrParam(rest, "TO:")
	if !ok {
		c.writef("%d 5.5.4 bad RCPT syntax", smtp.C501BadParamSyntax)
		return
	}
	addr, err := smtp.ParseAddress(addrStr)
	if err != nil {
		c.writef("%d 5.1.3 bad address", smtp.C501BadParamSyntax)
		return
	}
	// LIMITS RCPTMAX (RFC 9422): reject once the per-message recipient cap is hit.
	if len(c.rcpts)+len(c.subRcpts) >= c.srv.maxRcpt() {
		c.writef("452 4.5.3 too many recipients (RCPTMAX=%d)", c.srv.maxRcpt())
		return
	}
	if c.srv.Submission != nil {
		// Submission: sender must be authenticated; any recipient is accepted for
		// outbound relay.
		if !c.authed {
			c.writef("%d 5.7.1 authentication required", 530)
			return
		}
		c.subRcpts = append(c.subRcpts, addrStr)
		// Capture per-recipient DSN params (RFC 3461): NOTIFY=NEVER|SUCCESS,FAILURE,DELAY
		// and ORCPT=<original recipient>, parallel to subRcpts.
		c.subNotify = append(c.subNotify, mailParamStr(rest, "NOTIFY"))
		c.subORcpt = append(c.subORcpt, mailParamStr(rest, "ORCPT"))
		c.writef("%d 2.1.5 OK", smtp.C250Completed)
		return
	}
	// Mail to the VERP bounce/FBL domain belongs to no account: accept it and
	// route to the bounce handler after DATA (complaint/bounce → suppression).
	if c.srv.BounceDomain != "" && c.srv.BounceHandler != nil &&
		strings.EqualFold(addr.Domain.ASCII, c.srv.BounceDomain) {
		c.bounceRcpts = append(c.bounceRcpts, string(addr.Localpart))
		c.writef("%d 2.1.5 OK", smtp.C250Completed)
		return
	}
	target, err := c.srv.Dir.ResolveInbound(c.ctx, addr.Path())
	if err != nil {
		c.writef("%d 5.1.1 no such recipient", smtp.C550MailboxUnavail)
		return
	}
	c.rcpts = append(c.rcpts, target)
	c.rcptAddrs = append(c.rcptAddrs, addrStr)
	c.writef("%d 2.1.5 OK", smtp.C250Completed)
}

func (c *conn) cmdData() error {
	submission := c.srv.Submission != nil
	haveRcpt := len(c.rcpts) > 0 || len(c.bounceRcpts) > 0
	if submission {
		haveRcpt = len(c.subRcpts) > 0
	}
	if !c.haveFrom || !haveRcpt {
		return c.writef("%d 5.5.1 need MAIL and RCPT first", smtp.C503BadCmdSeq)
	}
	if err := c.writef("%d start mail input; end with <CRLF>.<CRLF>", smtp.C354Continue); err != nil {
		return err
	}
	// Reuse the dot-unstuffing reader. Bound the read so a client cannot
	// exhaust memory by streaming an unbounded body (the MAIL FROM SIZE= param is
	// advisory and easily omitted/understated); read one byte past the limit to
	// detect overflow.
	dr := smtp.NewDataReader(c.br)
	var data []byte
	var err error
	if c.srv.MaxSize > 0 {
		data, err = io.ReadAll(io.LimitReader(dr, c.srv.MaxSize+1))
		if err == nil && int64(len(data)) > c.srv.MaxSize {
			// Drain a bounded remainder to keep the command stream in sync, then
			// reject and clear transaction state (a pipelined follow-up must not
			// inherit this MAIL/RCPT). The drain is capped so a client cannot pin
			// the goroutine streaming an unbounded body after the reject.
			_, _ = io.Copy(io.Discard, io.LimitReader(dr, c.srv.MaxSize+1))
			c.reset()
			return c.writef("552 5.3.4 message exceeds size limit %d", c.srv.MaxSize)
		}
	} else {
		data, err = io.ReadAll(dr)
	}
	if err != nil {
		return c.writef("%d 4.3.0 error reading data", smtp.C451LocalErr)
	}
	return c.processData(data)
}

// cmdBDAT implements CHUNKING (RFC 3030): "BDAT <size> [LAST]". Each chunk is
// exactly <size> octets read verbatim (no dot-stuffing). Chunks accumulate until
// BDAT ... LAST, which triggers the same processing as DATA.
func (c *conn) cmdBDAT(rest string) error {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return c.writef("%d 5.5.4 BDAT needs a size", smtp.C501BadParamSyntax)
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 0 {
		return c.writef("%d 5.5.4 bad BDAT size", smtp.C501BadParamSyntax)
	}
	last := len(fields) >= 2 && strings.EqualFold(fields[1], "LAST")
	if !c.haveFrom || (len(c.rcpts) == 0 && len(c.subRcpts) == 0) {
		return c.writef("%d 5.5.1 need MAIL and RCPT first", smtp.C503BadCmdSeq)
	}
	// Reject an oversized chunk BEFORE allocating it — a client-controlled size
	// must not drive an unbounded allocation (OOM). Bound against MaxSize and what
	// has already accumulated across prior BDAT chunks.
	if c.srv.MaxSize > 0 && int64(n) > c.srv.MaxSize-int64(len(c.bdatBuf)) {
		c.reset()
		return c.writef("552 5.3.4 message too large")
	}
	// Read exactly n octets of chunk data verbatim.
	chunk := make([]byte, n)
	if _, err := io.ReadFull(c.br, chunk); err != nil {
		return c.writef("%d 4.3.0 error reading chunk", smtp.C451LocalErr)
	}
	c.inBDAT = true
	c.bdatBuf = append(c.bdatBuf, chunk...)
	if !last {
		return c.writef("%d 2.0.0 %d octets received", smtp.C250Completed, n)
	}
	data := c.bdatBuf
	return c.processData(data)
}

// cmdBURL implements BURL (RFC 4468): "BURL <imap-url> LAST". In submission mode
// the server fetches the message content from the authorized IMAP URL (RFC 4467
// URLAUTH) instead of the client sending it inline with DATA — letting a client
// submit a message it composed on the IMAP server without downloading it. The
// resolved content flows through the same submission path as DATA.
func (c *conn) cmdBURL(rest string) error {
	if c.srv.Submission == nil || c.srv.BURLResolver == nil {
		return c.writef("%d 5.5.1 BURL not available", smtp.C503BadCmdSeq)
	}
	if !c.authed {
		return c.writef("%d 5.7.0 authentication required", smtp.C503BadCmdSeq)
	}
	if !c.haveFrom || len(c.subRcpts) == 0 {
		return c.writef("%d 5.5.1 need MAIL and RCPT first", smtp.C503BadCmdSeq)
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 || !strings.EqualFold(fields[len(fields)-1], "LAST") {
		// We only support the single-URL "BURL <url> LAST" form.
		return c.writef("%d 5.5.4 BURL requires <url> LAST", smtp.C501BadParamSyntax)
	}
	url := fields[0]
	data, ok := c.srv.BURLResolver(c.ctx, c.authAccount, url)
	if !ok {
		// RFC 4468: 554 when the URL cannot be resolved/authorized.
		return c.writef("%d 5.7.0 BURL URL resolution failed", smtp.C554TransactionFailed)
	}
	if c.srv.MaxSize > 0 && int64(len(data)) > c.srv.MaxSize {
		c.reset()
		return c.writef("552 5.3.4 message too large")
	}
	return c.processData(data)
}

// processData handles a fully-received message body (from DATA or BDAT LAST):
// size check, submission-enqueue or MX authenticate+decide+deliver.
func (c *conn) processData(data []byte) error {
	submission := c.srv.Submission != nil
	if c.srv.MaxSize > 0 && int64(len(data)) > c.srv.MaxSize {
		c.reset()
		return c.writef("552 5.3.4 message too large")
	}

	// Mail to the VERP bounce/FBL domain: hand each VERP recipient to the bounce
	// handler (complaint/bounce → suppression) and accept. Never bounce a bounce.
	if len(c.bounceRcpts) > 0 && c.srv.BounceHandler != nil {
		for _, lp := range c.bounceRcpts {
			c.srv.BounceHandler(c.ctx, lp, data)
		}
		c.reset()
		return c.writef("%d 2.0.0 accepted", smtp.C250Completed)
	}

	if submission {
		// Enqueue to the shared outbound queue; the queue worker delivers. Carry
		// the RFC 3461 DSN params (RET/ENVID per-message, NOTIFY/ORCPT per-rcpt).
		dsnp := submit.DSNParams{Ret: c.dsnRet, EnvID: c.dsnEnvID}
		if hasDSNPerRcpt(c.subNotify) || hasDSNPerRcpt(c.subORcpt) {
			dsnp.Notify = make(map[string]string, len(c.subRcpts))
			dsnp.ORcpt = make(map[string]string, len(c.subRcpts))
			for i, r := range c.subRcpts {
				if i < len(c.subNotify) && c.subNotify[i] != "" {
					dsnp.Notify[r] = c.subNotify[i]
				}
				if i < len(c.subORcpt) && c.subORcpt[i] != "" {
					dsnp.ORcpt[r] = c.subORcpt[i]
				}
			}
		}
		_, err := c.srv.Submission.SubmitDSN(c.ctx, c.authTenant, c.authAccount, c.mailFrom, c.subRcpts, data, c.holdUntil, dsnp)
		c.reset()
		if err != nil {
			return c.writef("%d 4.3.0 could not enqueue: %v", smtp.C451LocalErr, err)
		}
		return c.writef("%d 2.0.0 queued", smtp.C250Completed)
	}

	// MX receive: authenticate the message (SPF/DKIM/DMARC/iprev/DNSBL), then
	// deliver to each resolved recipient's change-log with the auth header prefix.
	var authRes inbound.Result
	var sess inbound.Session
	authenticated := false
	if c.srv.Auth != nil {
		sess = inbound.Session{
			RemoteIP:    c.remoteIP(),
			HelloDomain: heloIPDomain(c.helo),
			MailFrom:    parsePathOrZero(c.mailFrom),
			Hostname:    dns.Domain{ASCII: c.host},
			TLS:         c.tls,
		}
		res, err := c.srv.Auth.Authenticate(c.ctx, sess, data)
		if err == nil {
			authRes = res
			authenticated = true
			// Record DMARC aggregate data for outbound report generation.
			if c.srv.DMARCRecorder != nil {
				if fd, ok2 := fromHeaderDomain(data); ok2 {
					disp := "none"
					if res.DMARC.Reject {
						disp = "reject"
					}
					c.srv.DMARCRecorder(c.ctx, fd, ipString(c.remoteIP()), string(res.SPF), dkimStatus(res), disp)
				}
			}
			// DNSBL-listed clients are rejected outright.
			if res.DNSBLZone != "" {
				c.reset()
				obs.InboundRejected.WithLabelValues("dnsbl").Inc()
				return c.writef("554 5.7.1 client IP listed by %s", res.DNSBLZone)
			}
			// DMARC reject policy (aligned failure), if enforcing.
			if c.srv.RejectDMARCFail && res.DMARC.Reject {
				c.reset()
				obs.InboundRejected.WithLabelValues("dmarc").Inc()
				return c.writef("550 5.7.1 rejected by DMARC policy")
			}
		}
	}

	senderDomain := ""
	if mf := parsePathOrZero(c.mailFrom); mf.IPDomain.Domain.ASCII != "" {
		senderDomain = mf.IPDomain.Domain.ASCII
	}
	// repAuthed reports whether senderDomain (the envelope MAIL FROM domain, which
	// inbound reputation is keyed on) is itself authenticated: an SPF pass whose
	// checked domain equals senderDomain. This must attest the SAME domain
	// reputation credits — not the From-header domain. DMARC alignment alone is
	// insufficient here: a DKIM-aligned message can carry an unrelated, unverified
	// envelope MAIL FROM, which would let an attacker build/leverage reputation on
	// a domain they don't control. Only aligned+matching SPF proves the envelope
	// domain, so only then may it earn or leverage a trusted reputation.
	repAuthed := authenticated && authRes.SPF == spf.StatusPass &&
		senderDomain != "" && strings.EqualFold(authRes.SPFDomain.ASCII, senderDomain)

	for i, target := range c.rcpts {
		m := &store.Message{}
		if authenticated {
			m.MsgPrefix = c.srv.Auth.Prefix(sess, authRes, c.rcptAddrs[i])
		}

		// Inbound decision: greylist + reputation + bayesian content. When a
		// Decider is configured it makes the accept/defer/reject call; otherwise
		// fall back to plain junk classification (route spam to Junk).
		mailbox := "Inbox"
		if c.srv.Decider != nil {
			var classify inbound.ClassifyFunc
			if c.srv.Junk != nil {
				classify = c.srv.Junk.Classify
			}
			dec := c.srv.Decider.Decide(c.ctx, target.AccountID(), senderDomain, c.remoteIP(), data, repAuthed, classify)
			switch dec.Verdict {
			case inbound.Defer:
				rcpt := c.rcptAddrs[i]
				c.reset()
				obs.InboundRejected.WithLabelValues("greylist").Inc()
				// A subjectpass challenge (if present) tells a legitimate sender how
				// to retry past a content rejection.
				if dec.Challenge != "" {
					return c.writef("451 4.7.1 message held; to pass, include %q in the Subject and resend", dec.Challenge)
				}
				return c.writef("451 4.7.1 greylisted, please retry later (%s)", rcpt)
			case inbound.Reject:
				c.reset()
				obs.InboundRejected.WithLabelValues("reputation").Inc()
				return c.writef("550 5.7.1 message rejected (%s)", dec.Reason)
			case inbound.AcceptJunk:
				mailbox = "Junk"
				m.Junk = true
			}
			// A ruleset match can force a specific destination mailbox.
			if dec.Mailbox != "" {
				mailbox = dec.Mailbox
			}
		} else if c.srv.Junk != nil {
			// Legacy path: classify only, route spam to Junk.
			if _, _, isJunk, err := c.srv.Junk.Classify(c.ctx, target.AccountID(), data); err == nil && isJunk {
				mailbox = "Junk"
				m.Junk = true
			}
		}
		var derr error
		if mailbox == "Inbox" {
			_, derr = target.Deliver(c.ctx, m, newBytesBlob(data))
		} else {
			_, derr = target.DeliverTo(c.ctx, mailbox, m, newBytesBlob(data))
		}
		if derr != nil {
			over := errors.Is(derr, store.ErrOverQuota)
			c.reset()
			if over {
				obs.InboundRejected.WithLabelValues("overquota").Inc()
				return c.writef("452 4.2.2 mailbox full for %s", c.rcptAddrs[i])
			}
			obs.InboundRejected.WithLabelValues("delivery_error").Inc()
			return c.writef("%d 4.3.0 delivery failed for %s", smtp.C451LocalErr, c.rcptAddrs[i])
		}
		// Record inbound reputation outcome (junk only when filed to Junk). Only
		// for reputation-authenticated senders (see repAuthed) — unauthenticated
		// mail must not build reputation.
		if c.srv.Decider != nil && senderDomain != "" {
			_ = c.srv.Decider.RecordOutcome(c.ctx, target.AccountID(), senderDomain, repAuthed, mailbox != "Junk")
		}
		// Vacation auto-reply: only for real Inbox deliveries (not Junk/rulesets).
		if c.srv.VacationResponder != nil && mailbox == "Inbox" && c.mailFrom != "" {
			c.srv.VacationResponder(c.ctx, target.AccountID(), c.mailFrom, c.rcptAddrs[i], data)
		}
		obs.InboundDelivered.WithLabelValues(strings.ToLower(mailbox)).Inc()
	}
	c.reset()
	return c.writef("%d 2.0.0 accepted", smtp.C250Completed)
}

// --- helpers ---

// remoteIP returns the client IP, or nil for pipes/unknown transports.
func (c *conn) remoteIP() net.IP {
	if a, ok := c.nc.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return nil
}

// heloIPDomain parses the EHLO/HELO argument into a dns.IPDomain (IP literal or
// domain). Best-effort: an unparseable value yields a zero IPDomain.
func heloIPDomain(helo string) dns.IPDomain {
	helo = strings.TrimSpace(helo)
	helo = strings.TrimPrefix(strings.TrimSuffix(helo, "]"), "[")
	if ip := net.ParseIP(helo); ip != nil {
		return dns.IPDomain{IP: ip}
	}
	if d, err := dns.ParseDomain(helo); err == nil {
		return dns.IPDomain{Domain: d}
	}
	return dns.IPDomain{}
}

// fromHeaderDomain extracts the From-header domain from raw message bytes using
// the canonical RFC 5322 parser (mox message.From), matching inbound.fromDomain
// — no hand-rolled header scanning, so folded headers, comments, display-name
// '@' signs, and group syntax are handled correctly.
func fromHeaderDomain(raw []byte) (string, bool) {
	addr, _, _, err := message.From(nil, false, byteReaderAt(raw), nil)
	if err != nil || addr.Domain.ASCII == "" {
		return "", false
	}
	return strings.ToLower(addr.Domain.ASCII), true
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ipString renders an IP for storage, or "unknown".
func ipString(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

// dkimStatus returns the first DKIM result status, or "none".
func dkimStatus(res inbound.Result) string {
	if len(res.DKIM) > 0 {
		return string(res.DKIM[0].Status)
	}
	return "none"
}

// parsePathOrZero parses an SMTP address into a smtp.Path, or a zero Path for an
// empty/invalid value (e.g. the null reverse-path of a DSN).
func parsePathOrZero(addr string) smtp.Path {
	if addr == "" {
		return smtp.Path{}
	}
	a, err := smtp.ParseAddress(addr)
	if err != nil {
		return smtp.Path{}
	}
	return a.Path()
}

func splitCmd(line string) (cmd, rest string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
}

// parseAddrParam extracts "<addr>" following a prefix like "FROM:" or "TO:".
// Tolerates optional space and trailing ESMTP params.
func parseAddrParam(rest, prefix string) (string, bool) {
	rest = strings.TrimSpace(rest)
	up := strings.ToUpper(rest)
	if !strings.HasPrefix(up, prefix) {
		return "", false
	}
	v := strings.TrimSpace(rest[len(prefix):])
	if !strings.HasPrefix(v, "<") {
		return "", false
	}
	end := strings.IndexByte(v, '>')
	if end < 0 {
		return "", false
	}
	addr := v[1:end]
	// "<>" (null return path) is valid for MAIL FROM but we treat empty as ok-ish
	// only for MAIL; RCPT with empty addr fails later at ParseAddress.
	return addr, true
}

// newBytesBlob wraps a byte slice as a store.BlobReader.
func newBytesBlob(b []byte) store.BlobReader {
	return &bytesBlob{Reader: bytes.NewReader(b), size: int64(len(b))}
}

type bytesBlob struct {
	*bytes.Reader
	size int64
}

func (b *bytesBlob) Size() int64  { return b.size }
func (b *bytesBlob) Close() error { return nil }
