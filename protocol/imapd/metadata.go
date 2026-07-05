package imapd

import (
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdGetMetadata implements GETMETADATA (RFC 5464). Forms accepted:
//
//	GETMETADATA <mailbox> <entry>
//	GETMETADATA <mailbox> (<entry> <entry> ...)
//
// where <mailbox> "" means the server entry set. Options like (MAXSIZE n /
// DEPTH d) preceding the mailbox are tolerated and ignored (we return all
// matching entries at or below each named entry). Responds with an untagged
// METADATA line per mailbox.
func (c *conn) cmdGetMetadata(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)
	// Skip an optional leading options list "(...)".
	if strings.HasPrefix(rest, "(") {
		if end := strings.IndexByte(rest, ')'); end >= 0 {
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	mbTok, entryTok := cut(rest, " ")
	mailbox := unquote(strings.TrimSpace(mbTok))
	entryTok = strings.TrimSpace(entryTok)

	var entries []string
	if strings.HasPrefix(entryTok, "(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(entryTok, "("), ")")
		for _, e := range strings.Fields(inner) {
			entries = append(entries, unquote(e))
		}
	} else if entryTok != "" {
		entries = append(entries, unquote(entryTok))
	}

	mbID, ok := c.metadataMailboxID(tag, mailbox)
	if !ok {
		return
	}
	anns, err := c.acc.AnnotationList(c.ctx, mbID, entries)
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	var parts []string
	for _, a := range anns {
		parts = append(parts, quote(a.Key)+" "+metadataValue(a))
	}
	if len(parts) > 0 {
		c.writef("* METADATA %s (%s)", quote(mailbox), strings.Join(parts, " "))
	}
	c.ok(tag, "GETMETADATA completed")
}

// cmdSetMetadata implements SETMETADATA (RFC 5464):
//
//	SETMETADATA <mailbox> (<entry> <value> <entry> <value> ...)
//
// value is a quoted string, a {n} literal, or NIL (removes the entry).
func (c *conn) cmdSetMetadata(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)
	mbTok, listTok := cut(rest, " ")
	mailbox := unquote(strings.TrimSpace(mbTok))
	listTok = strings.TrimSpace(listTok)
	if !strings.HasPrefix(listTok, "(") {
		c.no(tag, "expected entry/value list")
		return
	}
	// Drop the outer parens; parse key/value pairs, honoring literals inline.
	inner := strings.TrimSpace(listTok[1:])
	inner = strings.TrimSuffix(inner, ")")

	mbID, ok := c.metadataMailboxID(tag, mailbox)
	if !ok {
		return
	}

	// Parse key/value pairs. A value may be a {n} literal, whose payload arrives
	// on the wire after the command line; the remaining pairs then continue on
	// the line following the literal. We therefore process tokens from a running
	// queue, refilling it from the connection after each literal.
	toks := tokenizeMetadata(inner)
	for len(toks) >= 2 {
		key := unquote(toks[0])
		vraw := toks[1]
		toks = toks[2:]
		var value []byte
		switch {
		case strings.EqualFold(vraw, "NIL"):
			value = nil // removal
		case strings.HasPrefix(vraw, "{"):
			data, err := c.readLiteral(vraw)
			if err != nil {
				c.no(tag, "bad literal value: "+err.Error())
				return
			}
			value = data
			// The literal is followed by the rest of the list on the next wire
			// line (more pairs and/or the closing paren). Re-tokenize it so pairs
			// after a literal are not lost.
			cont, _ := c.readLine()
			cont = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cont), ")"))
			if cont != "" {
				toks = append(toks, tokenizeMetadata(cont)...)
			}
		default:
			value = []byte(unquote(vraw))
		}
		if err := c.acc.AnnotationSet(c.ctx, mbID, key, value, true); err != nil {
			c.no(tag, err.Error())
			return
		}
	}
	if len(toks) == 1 {
		c.no(tag, "odd entry/value list")
		return
	}
	c.ok(tag, "SETMETADATA completed")
}

// metadataMailboxID resolves the METADATA mailbox name to an id (0 = server
// entry for ""). Writes a tagged NO and returns ok=false on an unknown mailbox.
func (c *conn) metadataMailboxID(tag, mailbox string) (int64, bool) {
	if mailbox == "" {
		return 0, true
	}
	name := normalizeMailbox(mailbox)
	var id int64
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		mb, e := c.acc.MailboxFind(tx, name)
		if e != nil {
			return e
		}
		if mb == nil {
			return errNo("mailbox does not exist")
		}
		id = mb.ID
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return 0, false
	}
	return id, true
}

// metadataValue renders an annotation value: NIL when absent, else a quoted
// string (values are treated as UTF-8 strings in this implementation).
func metadataValue(a store.Annotation) string {
	if a.Value == nil {
		return "NIL"
	}
	return quote(string(a.Value))
}

// tokenizeMetadata splits an entry/value list on whitespace but keeps quoted
// strings and {n}/{n+} literal specs as single tokens. The literal payload
// itself is read separately from the connection by the caller.
func tokenizeMetadata(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				j++
			}
			if j < len(s) {
				j++ // include closing quote
			}
			toks = append(toks, s[i:j])
			i = j
		case '{':
			j := strings.IndexByte(s[i:], '}')
			if j < 0 {
				toks = append(toks, s[i:])
				i = len(s)
			} else {
				toks = append(toks, s[i:i+j+1])
				i = i + j + 1
			}
		default:
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks
}
