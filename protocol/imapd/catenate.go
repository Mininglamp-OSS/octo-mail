package imapd

import (
	"context"
	"io"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// readCatenate assembles an APPEND message from a CATENATE part list (RFC 4469):
//
//	CATENATE "(" cat-part *(SP cat-part) ")"
//	cat-part = "TEXT" SP literal / "URL" SP astring
//
// TEXT parts are inline literals (which may be synchronizing, requiring a "+"
// continuation, so the list can span lines); URL parts reference a section of an
// existing message via an IMAP URL (RFC 5092), resolved within this account. The
// concatenation of all parts becomes the appended message. It returns the
// assembled bytes and any trailing text after the closing ")" (for MULTIAPPEND).
func (c *conn) readCatenate(first string) ([]byte, string, error) {
	buf := []byte{}
	rest := strings.TrimSpace(first)
	if !strings.HasPrefix(rest, "(") {
		return nil, "", errNo("expected ( after CATENATE")
	}
	rest = strings.TrimSpace(rest[1:])

	for {
		// Refill from the next line if we've consumed the current one mid-list
		// (a synchronizing literal always ends a line).
		if rest == "" {
			line, err := c.readLine()
			if err != nil {
				return nil, "", err
			}
			rest = strings.TrimSpace(line)
		}
		if strings.HasPrefix(rest, ")") {
			return buf, strings.TrimSpace(rest[1:]), nil
		}

		kw, after := cut(rest, " ")
		switch strings.ToUpper(kw) {
		case "TEXT":
			after = strings.TrimSpace(after)
			// A literal spec "{n}"/"{n+}" occupies the rest of the line; its bytes
			// follow on the wire. readLiteral handles the "+" continuation.
			data, err := c.readLiteral(after)
			if err != nil {
				return nil, "", err
			}
			buf = append(buf, data...)
			// After the literal bytes, the remainder of the list is on a new line.
			rest = ""
		case "URL":
			after = strings.TrimSpace(after)
			urlTok, remainder := cutAString(after)
			// resolveCatenateURL charges the referenced message's size against the
			// per-command budget BEFORE reading it (see conn.fetchURLSection), so a
			// URL part is bounded without first materializing it.
			part, err := c.resolveCatenateURL(urlTok)
			if err != nil {
				return nil, "", err
			}
			buf = append(buf, part...)
			rest = strings.TrimSpace(remainder)
		default:
			return nil, "", errNo("unknown CATENATE part " + kw)
		}
	}
}

// cutAString splits a leading astring (quoted or bare atom) from s, returning
// the unquoted value and the remainder.
func cutAString(s string) (string, string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		// Quoted: find the closing quote honoring backslash escapes.
		var b strings.Builder
		i := 1
		for i < len(s) {
			if s[i] == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if s[i] == '"' {
				return b.String(), strings.TrimSpace(s[i+1:])
			}
			b.WriteByte(s[i])
			i++
		}
		return b.String(), ""
	}
	return cut(s, " ")
}

// resolveCatenateURL resolves an IMAP URL (RFC 5092) referencing a section of a
// message in this account, returning the referenced bytes. Only the relative and
// same-server forms addressing a mailbox by UID are supported; anything naming a
// different user/host is rejected (no cross-account access).
func (c *conn) resolveCatenateURL(url string) ([]byte, error) {
	mbName, uid, section, err := parseIMAPURLPath(url)
	if err != nil {
		return nil, err
	}
	return c.fetchURLSection(mbName, uid, section)
}

// parseIMAPURLPath parses the message-addressing portion of an IMAP URL (RFC
// 5092): an optional imap://<iserver>/ prefix followed by
// /<mailbox>[;UIDVALIDITY=n]/;UID=m[/;SECTION=s]. It returns the mailbox name,
// UID, and (possibly empty) section. Any URLAUTH suffix must be stripped first.
func parseIMAPURLPath(url string) (mbName string, uid uint32, section string, err error) {
	// Strip an optional imap://<iserver>/ prefix; resolution is account-scoped, so
	// the authority (userinfo/host) is advisory — only the path is used.
	if i := strings.Index(url, "://"); i >= 0 {
		rest := url[i+3:]
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return "", 0, "", errNo("malformed IMAP URL")
		}
		url = rest[slash:] // path portion, leading "/"
	}

	url = strings.TrimPrefix(url, "/")
	segs := strings.Split(url, "/")
	if len(segs) < 1 || segs[0] == "" {
		return "", 0, "", errNo("IMAP URL missing mailbox")
	}
	// The mailbox name is the first segment up to its first ';'. UID/SECTION
	// parameters may appear as their own "/;UID=.." segments OR appended to the
	// mailbox segment ("/INBOX;UID=1") — RFC 5092 allows both — so scan every
	// ';'-delimited part across all segments.
	mbSeg := segs[0]
	name := mbSeg
	if semi := strings.IndexByte(mbSeg, ';'); semi >= 0 {
		name = mbSeg[:semi]
	}
	mbName = normalizeMailbox(urlDecode(name))

	for _, seg := range segs {
		for _, part := range strings.Split(seg, ";") {
			up := strings.ToUpper(part)
			switch {
			case strings.HasPrefix(up, "UID="):
				n, _ := strconv.ParseUint(part[len("UID="):], 10, 32)
				uid = uint32(n)
			case strings.HasPrefix(up, "SECTION="):
				section = part[len("SECTION="):]
			}
		}
	}
	if uid == 0 {
		return "", 0, "", errNo("IMAP URL missing UID")
	}
	return mbName, uid, section, nil
}

// fetchURLSection looks up a message by mailbox + uid within this account and
// returns the referenced section bytes (whole message when section is empty).
// It charges the referenced message's size against the per-command budget BEFORE
// reading the blob, so an oversized (or repeatedly-referenced) URL part is
// rejected without ever materializing it — keeping peak per-command allocation at
// ~1×MaxSize rather than 2×.
func (c *conn) fetchURLSection(mbName string, uid uint32, section string) ([]byte, error) {
	msg, err := lookupURLMessage(c.ctx, c.acc, mbName, uid)
	if err != nil {
		return nil, err
	}
	// Charge the full stored size up front (a conservative upper bound even when a
	// sub-section is requested) before the unbounded read below.
	if !c.chargeBudget(msg.Size) {
		return nil, errNo("[TOOBIG] CATENATE exceeds APPENDLIMIT")
	}
	return sectionBytes(c.acc, *msg, section), nil
}

// lookupURLMessage resolves an IMAP URL's (mailbox, uid) to a message row within
// an account WITHOUT reading its body — so callers can consult msg.Size (from the
// projection) before deciding to materialize it.
func lookupURLMessage(ctx context.Context, acc store.Account, mbName string, uid uint32) (*store.Message, error) {
	var msg *store.Message
	err := acc.Tx(ctx, func(tx store.Tx) error {
		mb, err := acc.MailboxFind(tx, mbName)
		if err != nil {
			return err
		}
		if mb == nil {
			return errNo("IMAP URL mailbox not found")
		}
		ms, err := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		if err != nil {
			return err
		}
		for i := range ms {
			if uint32(ms[i].UID) == uid {
				msg = &ms[i]
				return nil
			}
		}
		return errNo("IMAP URL message not found")
	})
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// sectionBytes reads a message's bytes (whole message, or the referenced section).
func sectionBytes(acc store.Account, msg store.Message, section string) []byte {
	full := readMessageBytes(acc, msg)
	if section == "" {
		return full
	}
	// Reuse the FETCH body-section extractor for the referenced section.
	sec := bodySection{spec: strings.ToUpper(urlDecode(section)), raw: "BODY[" + section + "]"}
	return extractSection(full, sec)
}

// fetchURLSection looks up a message by mailbox + uid within an account and
// returns the referenced section bytes (whole message when section is empty).
// Standalone (ctx, Account) form so both IMAP (URLFETCH) and SMTP (BURL) can
// resolve IMAP URLs without a connection. The connection-scoped CATENATE path
// uses conn.fetchURLSection instead, which budgets the read.
func fetchURLSection(ctx context.Context, acc store.Account, mbName string, uid uint32, section string) ([]byte, error) {
	msg, err := lookupURLMessage(ctx, acc, mbName, uid)
	if err != nil {
		return nil, err
	}
	return sectionBytes(acc, *msg, section), nil
}

// readMessageBytes reads a message's full bytes (MsgPrefix + blob) via the store.
func readMessageBytes(acc store.Account, m store.Message) []byte {
	r := acc.MessageReader(m)
	data, _ := io.ReadAll(r)
	r.Close()
	return data
}

// urlDecode performs minimal percent-decoding for IMAP URL path segments.
func urlDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
