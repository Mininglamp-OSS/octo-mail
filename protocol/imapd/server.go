// Package imapd is a compact, real IMAP4 server bound to the octo-mail kernel
// (kernel/store + kernel/directory). It is intentionally minimal — enough of
// RFC 3501 for a real client to LOGIN, SELECT, FETCH, STORE, LIST, LOGOUT — and
// exists to prove the change-log kernel serves live IMAP: what SMTP delivery
// appended to the log, an IMAP client reads back. It is driven in tests by
// an unmodified imapclient.
//
// Every read/write goes through the kernel interfaces; there is no storage
// coupling here beyond kernel/store. IMAP MODSEQ is the account's changelog
// offset (store.ModSeq), so CONDSTORE/QRESYNC fall out for free later.
package imapd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/flate"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/ratelimit"
)

// Server serves IMAP over accepted connections, resolving logins through the
// directory (structural tenant isolation) and reading/writing via the kernel.
type Server struct {
	Dir directory.Directory

	// TLSConfig, when set, enables STARTTLS and (via ServeTLS) implicit TLS. When
	// set, plaintext LOGIN is refused before the connection is encrypted
	// (LOGINDISABLED / [PRIVACYREQUIRED]) — credentials never cross the wire in
	// the clear. When nil, the listener is plaintext-only (dev/tests behind a
	// trusted boundary).
	TLSConfig *tls.Config

	// LoginLimiter, when set, throttles authentication attempts per client IP to
	// blunt online password guessing. Counted on every LOGIN attempt; once the
	// window limit is hit, further attempts are refused before any credential
	// check (so a correct password mid-flood is still refused until the window
	// rolls). Nil = no limiting.
	LoginLimiter *ratelimit.Limiter

	// Junk, when set, is retrained when a message's \Junk flag changes or it is
	// moved into/out of the Junk mailbox: gaining \Junk (or entering Junk) trains
	// spam; losing it (or leaving Junk) trains ham. This is the feedback loop that
	// makes the bayesian filter learn from the user's corrections.
	Junk JunkTrainer

	// MaxSize bounds an accepted literal (APPEND/REPLACE/CATENATE/SETMETADATA), in
	// bytes, and is advertised as APPENDLIMIT. A literal declaring a larger size is
	// rejected before allocation, so a client can't force a multi-GB allocation per
	// connection. 0 = unlimited (dev/tests). Mirrors smtpd.Server.MaxSize.
	MaxSize int64
}

// JunkTrainer trains an account's junk filter on a message body.
type JunkTrainer interface {
	Train(ctx context.Context, accountID int64, ham bool, raw []byte) error
}

// Serve handles a single connection until logout/close. Blocking; callers run it
// per accepted conn (or in a goroutine).
func (s *Server) Serve(ctx context.Context, nc net.Conn) error {
	c := &conn{srv: s, ctx: ctx, nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	if _, ok := nc.(*tls.Conn); ok {
		c.tls = true
	}
	return c.serve()
}

// ServeTLS wraps nc in a TLS server handshake (implicit TLS, e.g. port 993)
// before serving. Requires TLSConfig.
func (s *Server) ServeTLS(ctx context.Context, nc net.Conn) error {
	if s.TLSConfig == nil {
		return fmt.Errorf("imapd: ServeTLS requires TLSConfig")
	}
	tc := tls.Server(nc, s.TLSConfig)
	if err := tc.Handshake(); err != nil {
		return err
	}
	return s.Serve(ctx, tc)
}

type conn struct {
	srv *Server
	ctx context.Context
	nc  net.Conn
	r   *bufio.Reader
	w   *bufio.Writer
	tls bool // connection is encrypted (implicit TLS or after STARTTLS)

	compress bool // COMPRESS=DEFLATE active
	flateW   *moxio.FlateWriter
	flateBW  *bufio.Writer

	qresync    bool // client issued ENABLE QRESYNC: EXPUNGE is reported as VANISHED
	uidonly    bool // client issued ENABLE UIDONLY (RFC 9586): seq-number commands rejected
	imap4rev2  bool // client issued ENABLE IMAP4rev2 (RFC 9051): rev2 response semantics
	utf8accept bool // client issued ENABLE UTF8=ACCEPT (RFC 6855)

	wmu        sync.Mutex // serializes writes to c.w (command loop + NOTIFY pusher)
	notifyStop func()     // cancels the active NOTIFY pusher; nil when NOTIFY not set

	fatal error // set by handlers to force connection close

	// cmdBudget is the remaining bytes a single command may RETAIN in memory,
	// reset to srv.MaxSize before each command. readLiteral and CATENATE URL parts
	// debit it, so a MULTIAPPEND or CATENATE that individually respects the
	// per-literal cap still can't accumulate N×MaxSize on one connection —
	// preserving the connection-cap sizing invariant (≈one message worth of buffer
	// per connection). cmdLimited records whether a limit is in force (MaxSize>0);
	// it MUST be tracked separately from cmdBudget because a command can legitimately
	// decrement cmdBudget to exactly 0 — overloading 0 as an "unlimited" sentinel
	// would misread an exhausted budget as unlimited and reopen the aggregate cap.
	//
	// Note this is a per-COMMAND cap, deliberately stricter than RFC 7889
	// APPENDLIMIT (a per-MESSAGE limit): a MULTIAPPEND whose messages are each
	// under APPENDLIMIT but together exceed MaxSize is rejected [TOOBIG]. That is a
	// memory-safety tradeoff, not a bug — a client can split such a batch into
	// separate APPEND commands.
	cmdBudget  int64
	cmdLimited bool

	scope    directory.TenantScope
	acc      store.Account
	selected *store.Mailbox
	readOnly bool

	// ftsHits caches per-term full-text hit sets during a single SEARCH command
	// (term → set of matching UIDs), so BODY/TEXT criteria use the async fts
	// projection once rather than scanning every message. Cleared after SEARCH.
	ftsHits map[string]map[store.UID]bool

	// savedSearch holds the last SEARCH RETURN (SAVE) result as UIDs (RFC 5182
	// SEARCHRES), referenced by "$" in a later command. Nil when unset.
	savedSearch []store.UID
}

// remoteIP returns the client IP for rate limiting, or 0.0.0.0 for pipes/unknown.
func (c *conn) remoteIP() net.IP {
	if a, ok := c.nc.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return net.IPv4zero
}

// capString reports the CAPABILITY token list for the current connection state.
// Before TLS on a TLS-required server, login is disabled and STARTTLS offered.
func (c *conn) capString() string {
	appendLimit := int64(math.MaxInt64)
	if c.srv.MaxSize > 0 {
		appendLimit = c.srv.MaxSize
	}
	caps := []string{"IMAP4rev2", "IMAP4rev1", "UIDPLUS", "MOVE", "NAMESPACE", "ENABLE", "CONDSTORE", "QRESYNC", "QUOTA", "QUOTA=RES-STORAGE", "REPLACE", "METADATA", "BINARY", "UIDONLY", "NOTIFY", "ESEARCH", "SEARCHRES", "WITHIN", "STATUS=SIZE", "MULTIAPPEND", "ID", "SASL-IR", "LITERAL+", "UTF8=ACCEPT", "APPENDLIMIT=" + strconv.FormatInt(appendLimit, 10), "LIST-EXTENDED", "LIST-STATUS", "LIST-METADATA", "SPECIAL-USE", "CREATE-SPECIAL-USE", "CHILDREN", "SORT", "THREAD=REFERENCES", "THREAD=ORDEREDSUBJECT", "SAVEDATE", "MULTISEARCH", "PREVIEW", "OBJECTID", "CATENATE", "URLAUTH", "INPROGRESS"}
	if !c.compress {
		caps = append(caps, "COMPRESS=DEFLATE")
	}
	if c.srv.TLSConfig != nil && !c.tls {
		caps = append(caps, "STARTTLS", "LOGINDISABLED")
	}
	// SCRAM-SHA-256 does not send the password in the clear, so it is offered
	// even before TLS (still subject to the login rate limiter). The channel-
	// binding variant SCRAM-SHA-256-PLUS is only meaningful over TLS.
	if _, ok := c.srv.Dir.(directory.SCRAMAuthenticator); ok {
		caps = append(caps, "AUTH=SCRAM-SHA-256")
		if c.tls {
			caps = append(caps, "AUTH=SCRAM-SHA-256-PLUS")
		}
	}
	return strings.Join(caps, " ")
}

func (c *conn) serve() error {
	// Greeting.
	defer c.stopNotify()
	c.writef("* OK [CAPABILITY %s] octo-mail ready", c.capString())
	c.flush()

	for {
		line, err := c.readLine()
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		tag, rest := cut(line, " ")
		cmd, args := cut(rest, " ")
		cmd = strings.ToUpper(cmd)
		// Reset the per-command memory budget: the total bytes this command may
		// retain across all its literals/parts (MULTIAPPEND, CATENATE). cmdLimited
		// is captured separately so an exact-fit exhaustion (budget → 0) is not
		// mistaken for "unlimited".
		c.cmdBudget = c.srv.MaxSize
		c.cmdLimited = c.srv.MaxSize > 0

		var done bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.writef("%s BAD %v", tag, r)
				}
			}()
			done = c.dispatch(tag, cmd, args)
		}()
		c.flush()
		if c.fatal != nil {
			return c.fatal
		}
		if done {
			return nil
		}
	}
}

// dispatch runs one command. Returns true when the connection should close
// (LOGOUT). Handlers panic a string on protocol/user errors, caught in serve.
func (c *conn) dispatch(tag, cmd, args string) bool {
	switch cmd {
	case "CAPABILITY":
		c.writef("* CAPABILITY %s", c.capString())
		c.ok(tag, "CAPABILITY completed")
	case "ID":
		// RFC 2971: exchange client/server implementation identity. We ignore the
		// client's parameter list and report our own name/version.
		c.writef(`* ID ("name" "octo-mail" "version" "0")`)
		c.ok(tag, "ID completed")
	case "NOOP":
		c.ok(tag, "NOOP completed")
	case "CHECK":
		if c.requireAuth(tag) {
			c.ok(tag, "CHECK completed")
		}
	case "ENABLE":
		// Enable recognized extensions and echo back exactly those that were
		// enabled (RFC 5161: the ENABLED response lists only recognized caps).
		// QRESYNC switches EXPUNGE reporting to VANISHED; IMAP4rev2/UTF8=ACCEPT
		// affect response formatting for the rest of the session.
		var enabled []string
		for _, w := range strings.Fields(strings.ToUpper(args)) {
			switch w {
			case "CONDSTORE":
				enabled = append(enabled, "CONDSTORE")
			case "QRESYNC":
				c.qresync = true
				enabled = append(enabled, "QRESYNC")
			case "UIDONLY":
				c.uidonly = true
				enabled = append(enabled, "UIDONLY")
			case "IMAP4REV2":
				c.imap4rev2 = true
				enabled = append(enabled, "IMAP4rev2")
			case "UTF8=ACCEPT":
				c.utf8accept = true
				enabled = append(enabled, "UTF8=ACCEPT")
			}
		}
		c.writef("* ENABLED %s", strings.Join(enabled, " "))
		c.ok(tag, "ENABLE completed")
	case "NAMESPACE":
		c.cmdNamespace(tag)
	case "GETMETADATA":
		c.cmdGetMetadata(tag, args)
	case "SETMETADATA":
		c.cmdSetMetadata(tag, args)
	case "NOTIFY":
		c.cmdNotify(tag, args)
	case "STATUS":
		c.cmdStatus(tag, args)
	case "GETQUOTA":
		c.cmdGetQuota(tag, args, false)
	case "GETQUOTAROOT":
		c.cmdGetQuota(tag, args, true)
	case "LSUB":
		c.cmdLsub(tag, args)
	case "CLOSE":
		c.cmdClose(tag, true)
	case "UNSELECT":
		c.cmdClose(tag, false)
	case "STARTTLS":
		c.cmdStartTLS(tag)
	case "LOGIN":
		c.cmdLogin(tag, args)
	case "AUTHENTICATE":
		c.cmdAuthenticate(tag, args)
	case "SELECT":
		c.cmdSelect(tag, args, false)
	case "EXAMINE":
		c.cmdSelect(tag, args, true)
	case "CREATE":
		c.cmdCreate(tag, args)
	case "DELETE":
		c.cmdDelete(tag, args)
	case "RENAME":
		c.cmdRename(tag, args)
	case "SUBSCRIBE":
		c.cmdSubscribe(tag, args, true)
	case "UNSUBSCRIBE":
		c.cmdSubscribe(tag, args, false)
	case "APPEND":
		c.cmdAppend(tag, args)
	case "EXPUNGE":
		c.cmdExpunge(tag, "", false)
	case "LIST":
		c.cmdList(tag, args)
	case "FETCH":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdFetch(tag, args, false)
	case "STORE":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdStore(tag, args, false)
	case "SEARCH":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdSearch(tag, args, false)
	case "ESEARCH":
		c.cmdESearch(tag, args)
	case "SORT":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdSort(tag, args, false)
	case "THREAD":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdThread(tag, args, false)
	case "COPY":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdCopyMove(tag, args, false, false)
	case "MOVE":
		if c.rejectSeqIfUIDOnly(tag) {
			return false
		}
		c.cmdCopyMove(tag, args, false, true)
	case "IDLE":
		c.cmdIdle(tag)
	case "REPLACE":
		c.cmdReplace(tag, args, false)
	case "COMPRESS":
		c.cmdCompress(tag, args)
	case "GENURLAUTH":
		c.cmdGenURLAuth(tag, args)
	case "URLFETCH":
		c.cmdURLFetch(tag, args)
	case "RESETKEY":
		c.cmdResetKey(tag, args)
	case "UID":
		sub, rest := cut(args, " ")
		switch strings.ToUpper(sub) {
		case "FETCH":
			c.cmdFetch(tag, rest, true)
		case "STORE":
			c.cmdStore(tag, rest, true)
		case "SEARCH":
			c.cmdSearch(tag, rest, true)
		case "SORT":
			c.cmdSort(tag, rest, true)
		case "THREAD":
			c.cmdThread(tag, rest, true)
		case "COPY":
			c.cmdCopyMove(tag, rest, true, false)
		case "MOVE":
			c.cmdCopyMove(tag, rest, true, true)
		case "EXPUNGE":
			c.cmdExpunge(tag, rest, true)
		case "REPLACE":
			c.cmdReplace(tag, rest, true)
		default:
			c.no(tag, "unsupported UID command")
		}
	case "LOGOUT":
		c.writef("* BYE logging out")
		c.ok(tag, "LOGOUT completed")
		return true
	default:
		c.no(tag, "command not supported")
	}
	return false
}

// rejectSeqIfUIDOnly returns true (and emits a tagged BAD [UIDREQUIRED]) when the
// session enabled UIDONLY and a message-sequence-number command was issued. Per
// RFC 9586, such clients must use the UID variants exclusively.
func (c *conn) rejectSeqIfUIDOnly(tag string) bool {
	if c.uidonly {
		c.writef("%s BAD [UIDREQUIRED] sequence numbers not allowed after ENABLE UIDONLY", tag)
		return true
	}
	return false
}

// cmdStartTLS upgrades the connection to TLS in place. After the tagged OK, the
// client initiates the handshake; we wrap the underlying conn as a TLS server
// and reset our buffered reader/writer onto it. Refused if already encrypted or
// if the server has no TLS config.
func (c *conn) cmdStartTLS(tag string) {
	if c.srv.TLSConfig == nil {
		c.no(tag, "STARTTLS not available")
		return
	}
	if c.tls {
		c.no(tag, "already using TLS")
		return
	}
	c.ok(tag, "begin TLS negotiation now")
	c.flush()
	tc := tls.Server(c.nc, c.srv.TLSConfig)
	if err := tc.Handshake(); err != nil {
		// Handshake failed: the wire is in an unknown state; close.
		c.fatal = err
		return
	}
	c.nc = tc
	c.r = bufio.NewReader(tc)
	c.w = bufio.NewWriter(tc)
	c.tls = true
}

// cmdCompress implements COMPRESS=DEFLATE (RFC 4978): after the tagged OK, both
// directions are wrapped in a raw DEFLATE stream. We reuse the FlateWriter (for
// correct partial-flush framing) and flate.NewReaderPartial (which returns data
// on partial flushes rather than blocking on the stdlib flate reader). args:
// "DEFLATE".
func (c *conn) cmdCompress(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	alg := strings.ToUpper(strings.TrimSpace(args))
	if alg == "" {
		c.no(tag, "compression algorithm required")
		return
	}
	if alg != "DEFLATE" {
		c.no(tag, "compression algorithm not supported")
		return
	}
	if c.compress {
		c.no(tag, "[COMPRESSIONACTIVE] compression already active")
		return
	}
	// Send the OK uncompressed, then flush before switching the streams.
	c.ok(tag, "DEFLATE active")
	c.flush()

	// Writer: our bufio -> FlateWriter -> bufio(conn). Keep flateW/flateBW so
	// flush() can drain the deflate stream all the way to the socket.
	c.flateBW = bufio.NewWriter(c.nc)
	fw0, err := flate.NewWriter(c.flateBW, flate.DefaultCompression)
	if err != nil {
		c.fatal = err
		return
	}
	c.flateW = moxio.NewFlateWriter(fw0)
	c.w = bufio.NewWriter(c.flateW)

	// Reader: bytes already buffered in c.r must be presented before reading more
	// from the socket, then everything is inflated. NewReaderPartial returns data
	// on partial flushes (many clients flush that way) instead of blocking.
	rc := prefixConn(c.nc, c.r)
	fr := flate.NewReaderPartial(rc)
	c.r = bufio.NewReader(fr)
	c.compress = true
}

// --- response helpers ---
func (c *conn) writef(format string, a ...any) {
	c.wmu.Lock()
	fmt.Fprintf(c.w, format+"\r\n", a...)
	c.wmu.Unlock()
}
func (c *conn) ok(tag, msg string) { c.writef("%s OK %s", tag, msg) }
func (c *conn) no(tag, msg string) { c.writef("%s NO %s", tag, msg) }
func (c *conn) flush() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.w.Flush()
	// When compression is active, drain the flate writer and its underlying
	// buffered writer so bytes actually reach the socket.
	if c.compress && c.flateW != nil {
		_ = c.flateW.Flush()
		_ = c.flateBW.Flush()
	}
}

func (c *conn) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		if err == io.EOF && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// cut splits s on the first sep; if absent, returns (s, "").
func cut(s, sep string) (string, string) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return s, ""
}

// prefixConn returns a net.Conn that first yields any bytes already buffered in
// br, then reads from nc. Used when switching to a compressed stream: the flate
// reader must see bytes the bufio.Reader already consumed from the socket.
func prefixConn(nc net.Conn, br *bufio.Reader) net.Conn {
	n := br.Buffered()
	if n == 0 {
		return nc
	}
	buf := make([]byte, n)
	_, _ = io.ReadFull(br, buf)
	return &prefixConnT{prefix: buf, Conn: nc}
}

type prefixConnT struct {
	prefix []byte
	net.Conn
}

func (c *prefixConnT) Read(buf []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(buf, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(buf)
}
