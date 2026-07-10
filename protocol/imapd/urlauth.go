package imapd

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// URLAUTH (RFC 4467) lets a client mint an authorized IMAP URL: a URL whose
// ";URLAUTH=<access>" rump is bound to an HMAC token keyed by a per-mailbox
// secret. GENURLAUTH mints the token, URLFETCH validates it and returns the
// referenced content (so a third party — e.g. a submission server — can pull the
// content without the user's password), and RESETKEY rotates the secret to
// revoke previously-minted URLs.

// cmdGenURLAuth implements GENURLAUTH: "GENURLAUTH url-rump mechanism ...". For
// each (rump, mechanism) pair it appends ":<mech>:<token>" and returns the full
// authorized URL. Only the INTERNAL mechanism is supported.
func (c *conn) cmdGenURLAuth(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	toks := splitQuotedFields(strings.TrimSpace(args))
	if len(toks) < 2 || len(toks)%2 != 0 {
		c.no(tag, "GENURLAUTH needs url-rump/mechanism pairs")
		return
	}
	var full []string
	for i := 0; i+1 < len(toks); i += 2 {
		rump := toks[i]
		mech := strings.ToUpper(toks[i+1])
		if mech != "INTERNAL" {
			c.no(tag, "unsupported URLAUTH mechanism")
			return
		}
		token, err := c.urlauthToken(rump)
		if err != nil {
			c.no(tag, "GENURLAUTH failed: "+err.Error())
			return
		}
		full = append(full, rump+":internal:"+token)
	}
	c.writef("* GENURLAUTH %s", strings.Join(quoteEach(full), " "))
	c.ok(tag, "GENURLAUTH completed")
}

// cmdURLFetch implements URLFETCH: "URLFETCH authurl ...". For each URL it
// validates the token and returns the referenced content as a literal, or NIL on
// any failure (RFC 4467 §4: never distinguish failure reasons).
func (c *conn) cmdURLFetch(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	urls := splitQuotedFields(strings.TrimSpace(args))
	if len(urls) == 0 {
		c.no(tag, "URLFETCH needs a URL")
		return
	}
	for _, u := range urls {
		data, ok := c.urlauthResolve(u)
		// Emit the untagged URLFETCH under the write lock so the NOTIFY pusher
		// cannot splice output into the middle of the literal.
		c.wmu.Lock()
		if !ok {
			fmt.Fprintf(c.w, "* URLFETCH %s NIL\r\n", quote(u))
		} else {
			fmt.Fprintf(c.w, "* URLFETCH %s {%d}\r\n", quote(u), len(data))
			c.w.Write(data)
			fmt.Fprint(c.w, "\r\n")
		}
		c.wmu.Unlock()
	}
	c.ok(tag, "URLFETCH completed")
}

// cmdResetKey implements RESETKEY: "RESETKEY [mailbox [mechanism...]]". With a
// mailbox it rotates that mailbox's access key (revoking its URLs) and returns
// the new key in a URLMECH response code; with no argument it drops all keys.
func (c *conn) cmdResetKey(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) == 0 {
		if err := c.acc.URLAuthResetAll(c.ctx); err != nil {
			c.no(tag, err.Error())
			return
		}
		c.ok(tag, "all keys removed")
		return
	}
	mbName := normalizeMailbox(unquote(fields[0]))
	var mbID int64
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		mb, err := c.acc.MailboxFind(tx, mbName)
		if err != nil {
			return err
		}
		if mb == nil {
			return errNo("mailbox not found")
		}
		mbID = mb.ID
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	key, err := c.acc.URLAuthResetKey(c.ctx, mbID)
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	// Report the new key material (base64) in the URLMECH code, per RFC 4467.
	c.ok(tag, "[URLMECH INTERNAL="+hex.EncodeToString(key)+"] key reset")
}

// urlauthToken computes the INTERNAL HMAC-SHA1 token over a url-rump, keyed by
// the access key of the mailbox the URL addresses. The rump must end in
// ";URLAUTH=<access>" (RFC 4467 §3).
func (c *conn) urlauthToken(rump string) (string, error) {
	return urlauthToken(c.ctx, c.acc, rump)
}

func urlauthToken(ctx context.Context, acc store.Account, rump string) (string, error) {
	mbName, _, _, err := parseIMAPURLPath(stripURLAuth(rump))
	if err != nil {
		return "", err
	}
	var mbID int64
	err = acc.ReadTx(ctx, func(tx store.Tx) error {
		mb, e := acc.MailboxFind(tx, mbName)
		if e != nil {
			return e
		}
		if mb == nil {
			return errNo("mailbox not found")
		}
		mbID = mb.ID
		return nil
	})
	if err != nil {
		return "", err
	}
	key, err := acc.URLAuthKey(ctx, mbID)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(rump))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// urlauthResolve validates an authorized URL's token and returns the referenced
// content. ok is false on any validation or resolution failure.
func (c *conn) urlauthResolve(authurl string) ([]byte, bool) {
	return ResolveURLAuth(c.ctx, c.acc, authurl)
}

// ResolveURLAuth validates an RFC 4467 authorized URL against an account and
// returns the referenced content. ok is false on any validation or resolution
// failure (never distinguish reasons). Exported so the SMTP submission server
// can consume URLAUTH URLs via BURL (RFC 4468).
func ResolveURLAuth(ctx context.Context, acc store.Account, authurl string) ([]byte, bool) {
	// Split the rump from ":<mech>:<token>" — the URLAUTH token is always last.
	i := strings.LastIndex(strings.ToLower(authurl), ":internal:")
	if i < 0 {
		return nil, false
	}
	rump := authurl[:i]
	token := authurl[i+len(":internal:"):]

	want, err := urlauthToken(ctx, acc, rump)
	if err != nil {
		return nil, false
	}
	if !hmac.Equal([]byte(strings.ToLower(token)), []byte(strings.ToLower(want))) {
		return nil, false
	}
	mbName, uid, section, err := parseIMAPURLPath(stripURLAuth(rump))
	if err != nil {
		return nil, false
	}
	data, err := fetchURLSection(ctx, acc, mbName, uid, section)
	if err != nil {
		return nil, false
	}
	return data, true
}

// stripURLAuth removes a trailing ";URLAUTH=..." (and optional ";EXPIRE=...")
// component so the path can be parsed by parseIMAPURLPath.
func stripURLAuth(rump string) string {
	if i := strings.Index(strings.ToUpper(rump), ";URLAUTH="); i >= 0 {
		rump = rump[:i]
	}
	if i := strings.Index(strings.ToUpper(rump), ";EXPIRE="); i >= 0 {
		rump = rump[:i]
	}
	return rump
}

func quoteEach(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = quote(s)
	}
	return out
}
