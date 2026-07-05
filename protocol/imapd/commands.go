package imapd

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
)

// unquote removes surrounding double-quotes if present.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func (c *conn) cmdLogin(tag, args string) {
	// Refuse plaintext credentials before the connection is encrypted: on a
	// TLS-capable server the password must not cross the wire in the clear.
	if c.srv.TLSConfig != nil && !c.tls {
		c.no(tag, "[PRIVACYREQUIRED] LOGIN disabled until STARTTLS")
		return
	}
	// Brute-force throttle: count every attempt per client IP; refuse once the
	// window limit is exceeded, before any credential check.
	if c.srv.LoginLimiter != nil {
		if !c.srv.LoginLimiter.Add(c.remoteIP(), time.Now(), 1) {
			c.no(tag, "[UNAVAILABLE] too many login attempts, slow down")
			return
		}
	}

	userTok, passTok := cut(args, " ")
	user := unquote(userTok)
	pass := unquote(passTok)

	addr, err := smtp.ParseAddress(user)
	if err != nil {
		c.no(tag, "invalid login address")
		return
	}
	// Authenticate via the directory with the presented password.
	scope, _, err := c.srv.Dir.AuthenticatePrincipal(c.ctx, user, directory.PasswordCredential(pass))
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	acc, err := scope.AccountForAddress(c.ctx, addr.Path())
	if err != nil {
		c.no(tag, "no such account")
		return
	}
	c.scope = scope
	c.acc = acc
	c.ok(tag, "[CAPABILITY IMAP4rev1 UIDPLUS] logged in")
}

// cmdAuthenticate implements SASL AUTHENTICATE. Two mechanisms are supported:
// SCRAM-SHA-256 and its channel-binding variant SCRAM-SHA-256-PLUS. The client
// proves knowledge of the password via challenge/response, so the secret never
// crosses the wire — SCRAM-SHA-256 is safe to offer even before STARTTLS. The
// -PLUS variant binds the SCRAM exchange to the TLS channel (RFC 5802/9266),
// defeating an authenticated MITM, and is offered only over TLS.
func (c *conn) cmdAuthenticate(tag, args string) {
	sa, ok := c.srv.Dir.(directory.SCRAMAuthenticator)
	if !ok {
		c.no(tag, "AUTHENTICATE not available")
		return
	}
	mech, rest := cut(strings.TrimSpace(args), " ")
	plus := strings.EqualFold(mech, "SCRAM-SHA-256-PLUS")
	if !plus && !strings.EqualFold(mech, "SCRAM-SHA-256") {
		c.no(tag, "unsupported SASL mechanism")
		return
	}
	// Channel binding requires an active TLS connection.
	var cs *tls.ConnectionState
	if plus {
		tc, ok := c.nc.(*tls.Conn)
		if !ok {
			c.no(tag, "SCRAM-SHA-256-PLUS requires TLS")
			return
		}
		st := tc.ConnectionState()
		cs = &st
	}
	// Rate-limit auth attempts (same budget as LOGIN).
	if c.srv.LoginLimiter != nil && !c.srv.LoginLimiter.Add(c.remoteIP(), time.Now(), 1) {
		c.no(tag, "[UNAVAILABLE] too many login attempts, slow down")
		return
	}

	// Initial client response: may be inline (SASL-IR) or requested via a bare
	// continuation.
	var clientFirst []byte
	if rest != "" {
		b, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			c.no(tag, "invalid base64 in initial response")
			return
		}
		clientFirst = b
	} else {
		c.writef("+ ")
		c.flush()
		line, err := c.readLine()
		if err != nil {
			c.fatal = err
			return
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			c.no(tag, "invalid base64")
			return
		}
		clientFirst = b
	}

	srv, err := scram.NewServer(sha256.New, clientFirst, cs, plus)
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	login := srv.Authentication
	ver, err := sa.LookupSCRAM(c.ctx, login)
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	serverFirst, err := srv.ServerFirst(ver.Iterations, ver.Salt)
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	c.writef("+ %s", base64.StdEncoding.EncodeToString([]byte(serverFirst)))
	c.flush()

	// Client final message.
	line, err := c.readLine()
	if err != nil {
		c.fatal = err
		return
	}
	clientFinal, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		c.no(tag, "invalid base64")
		return
	}
	serverFinal, err := srv.Finish(clientFinal, ver.SaltedPassword)
	if err != nil {
		// Send the SCRAM error as a final failure.
		c.no(tag, "authentication failed")
		return
	}
	// Send server-final in a continuation; client replies with an empty line.
	c.writef("+ %s", base64.StdEncoding.EncodeToString([]byte(serverFinal)))
	c.flush()
	if _, err := c.readLine(); err != nil {
		c.fatal = err
		return
	}

	// Proof verified. Resolve the tenant scope and the account (no credential
	// check here — ScopeForLogin trusts the completed SCRAM proof).
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	scope, _, err := sa.ScopeForLogin(c.ctx, login)
	if err != nil {
		c.no(tag, "authentication failed")
		return
	}
	acc, err := scope.AccountForAddress(c.ctx, addr.Path())
	if err != nil {
		c.no(tag, "no such account")
		return
	}
	c.scope = scope
	c.acc = acc
	c.ok(tag, "[CAPABILITY IMAP4rev1 UIDPLUS] authenticated")
}

func (c *conn) requireAuth(tag string) bool {
	if c.acc == nil {
		c.no(tag, "not authenticated")
		return false
	}
	return true
}

func (c *conn) cmdSelect(tag, args string, readOnly bool) {
	if !c.requireAuth(tag) {
		return
	}
	// Optional QRESYNC parameter: SELECT <mbox> (QRESYNC (<uidvalidity> <modseq>
	// [<known-uids>])). RFC 7162 §3.2.5. We split the mailbox name from a trailing
	// parenthesized parameter list.
	name := args
	var qr *qresyncParams
	if i := strings.IndexByte(args, '('); i >= 0 {
		name = strings.TrimSpace(args[:i])
		qr = parseQResync(args[i:])
	}
	name = unquote(strings.TrimSpace(name))
	if strings.EqualFold(name, "INBOX") {
		name = "Inbox"
	}

	var mb *store.Mailbox
	var msgs []store.Message
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		m, err := c.acc.MailboxFind(tx, name)
		if err != nil {
			return err
		}
		if m == nil {
			return errNo("mailbox does not exist")
		}
		mb = m
		msgs, err = tx.QueryMessage().FilterMailbox(m.ID).SortUID().List()
		return err
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	c.selected = mb
	c.readOnly = readOnly

	// If NOTIFY is active, re-point its pusher at the newly-selected mailbox
	// (it captured the previous mailbox id at NOTIFY SET time).
	if c.notifyStop != nil {
		c.stopNotify()
		c.startNotify()
	}

	c.writef(`* FLAGS (\Seen \Answered \Flagged \Deleted \Draft)`)
	c.writef(`* OK [PERMANENTFLAGS (\Seen \Answered \Flagged \Deleted \Draft \*)] limited`)
	c.writef("* %d EXISTS", len(msgs))
	if !c.imap4rev2 {
		// RECENT was removed in IMAP4rev2 (RFC 9051); only send it for rev1.
		c.writef("* 0 RECENT")
	}
	c.writef("* OK [UIDVALIDITY %d] uids valid", mb.UIDValidity)
	c.writef("* OK [UIDNEXT %d] predicted next uid", mb.UIDNext)
	c.writef("* OK [HIGHESTMODSEQ %d] highest", mb.ModSeq)
	c.writef("* OK [MAILBOXID (%s)] object id", mailboxObjectID(mb.ID))

	// QRESYNC fast-resync: if the client's UIDVALIDITY matches, report what
	// vanished and what changed since its modseq, so it can converge without a
	// full resynchronization. RFC 7162 §3.2.5.2.
	if qr != nil && qr.uidValidity == mb.UIDValidity && qr.modSeq >= 0 {
		c.qresyncReport(mb, msgs, qr)
	}

	if readOnly {
		c.ok(tag, "[READ-ONLY] examined")
	} else {
		c.ok(tag, "[READ-WRITE] selected")
	}
}

// qresyncParams holds the parsed SELECT ... (QRESYNC (...)) arguments.
type qresyncParams struct {
	uidValidity uint32
	modSeq      int64
	knownUIDs   string // optional known-uids set (sequence-set syntax), may be ""
}

// parseQResync parses "(QRESYNC (<uidvalidity> <modseq> [<known-uids>]))".
// Returns nil if the parameter is absent or malformed.
func parseQResync(s string) *qresyncParams {
	up := strings.ToUpper(s)
	i := strings.Index(up, "QRESYNC")
	if i < 0 {
		return nil
	}
	rest := s[i+len("QRESYNC"):]
	// Find the inner "(...)" holding the values.
	lp := strings.IndexByte(rest, '(')
	if lp < 0 {
		return nil
	}
	rp := strings.IndexByte(rest[lp:], ')')
	if rp < 0 {
		return nil
	}
	inner := rest[lp+1 : lp+rp]
	f := strings.Fields(inner)
	if len(f) < 2 {
		return nil
	}
	uv, err1 := strconv.ParseUint(f[0], 10, 32)
	ms, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	q := &qresyncParams{uidValidity: uint32(uv), modSeq: ms}
	if len(f) >= 3 {
		q.knownUIDs = f[2]
	}
	return q
}

// qresyncReport emits VANISHED (EARLIER) for UIDs expunged since the client's
// modseq, and a FETCH (with FLAGS + MODSEQ) for messages changed since then, so
// a reconnecting client converges its view. RFC 7162 §3.2.5.
func (c *conn) qresyncReport(mb *store.Mailbox, msgs []store.Message, qr *qresyncParams) {
	// VANISHED (EARLIER): UIDs the change-log records as expunged after modSeq.
	vanished, err := c.acc.ExpungedUIDsSince(c.ctx, mb.ID, store.ModSeq(qr.modSeq))
	if err == nil && len(vanished) > 0 {
		// Optionally restrict to the client's known-uids set (RFC 7162: a client
		// may pass the UIDs it still knows; we only need to report those).
		var filter func(uint32) bool
		if qr.knownUIDs != "" {
			filter = parseUIDSet(qr.knownUIDs, uint32(mb.UIDNext))
		}
		var ids []string
		for _, u := range vanished {
			if filter != nil && !filter(uint32(u)) {
				continue
			}
			ids = append(ids, strconv.FormatUint(uint64(u), 10))
		}
		if len(ids) > 0 {
			c.writef("* VANISHED (EARLIER) %s", compressUIDList(ids))
		}
	}

	// Changed messages: those whose modseq > the client's modseq, reported with
	// FLAGS + MODSEQ so the client refreshes them.
	seqOf := map[store.UID]uint32{}
	for i, m := range msgs {
		seqOf[m.UID] = uint32(i + 1)
	}
	for _, m := range msgs {
		if int64(m.ModSeq) <= qr.modSeq {
			continue
		}
		c.writef("* %d FETCH (UID %d MODSEQ (%d) FLAGS (%s))",
			seqOf[m.UID], m.UID, m.ModSeq, strings.Join(flagStrings(m), " "))
	}
}

// compressUIDList collapses a sorted list of decimal UID strings into IMAP
// sequence-set ranges ("1,3:5,9"). Input must be ascending.
func compressUIDList(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	nums := make([]uint64, 0, len(ids))
	for _, s := range ids {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return strings.Join(ids, ",")
		}
		nums = append(nums, n)
	}
	var parts []string
	start := nums[0]
	prev := nums[0]
	flush := func(lo, hi uint64) {
		if lo == hi {
			parts = append(parts, strconv.FormatUint(lo, 10))
		} else {
			parts = append(parts, strconv.FormatUint(lo, 10)+":"+strconv.FormatUint(hi, 10))
		}
	}
	for _, n := range nums[1:] {
		if n == prev+1 {
			prev = n
			continue
		}
		flush(start, prev)
		start, prev = n, n
	}
	flush(start, prev)
	return strings.Join(parts, ",")
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// errNo is a user-facing error carried through panics/returns.
type errNo string

func (e errNo) Error() string { return string(e) }

// parseUIDSet parses a minimal UID set: "N", "N:M", "N:*", "1:*", comma lists.
// Returns a matcher over uid values. maxUID is the largest present uid (for *).
func parseUIDSet(s string, maxUID uint32) func(uint32) bool {
	type rng struct{ lo, hi uint32 }
	var ranges []rng
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := part, "", false
		if i := strings.Index(part, ":"); i >= 0 {
			lo, hi, isRange = part[:i], part[i+1:], true
		}
		parse := func(x string) uint32 {
			if x == "*" {
				return maxUID
			}
			n, _ := strconv.ParseUint(x, 10, 32)
			return uint32(n)
		}
		l := parse(lo)
		h := l
		if isRange {
			h = parse(hi)
		}
		if l > h {
			l, h = h, l
		}
		ranges = append(ranges, rng{l, h})
	}
	return func(uid uint32) bool {
		for _, r := range ranges {
			if uid >= r.lo && uid <= r.hi {
				return true
			}
		}
		return false
	}
}
