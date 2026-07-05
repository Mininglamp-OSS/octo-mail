package imapd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// searchNode evaluates one message against a parsed SEARCH criteria tree.
type searchNode interface {
	match(c *conn, m store.Message, seq, total uint32) bool
}

// --- tokenizer ---

// tokenizeSearch splits a SEARCH argument into tokens, honoring double-quoted
// strings (which may contain spaces) and parentheses as their own tokens.
func tokenizeSearch(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == ' ' || ch == '\t':
			i++
		case ch == '(' || ch == ')':
			toks = append(toks, string(ch))
			i++
		case ch == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			toks = append(toks, b.String())
			i = j + 1
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '(' && s[j] != ')' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks
}

// --- parser: returns an implicit-AND of criteria until end or ')' ---

func parseSearchSeq(toks []string, pos int) (searchNode, int, error) {
	var nodes []searchNode
	for pos < len(toks) {
		if toks[pos] == ")" {
			break
		}
		n, np, err := parseSearchOne(toks, pos)
		if err != nil {
			return nil, pos, err
		}
		nodes = append(nodes, n)
		pos = np
	}
	if len(nodes) == 0 {
		return sAll{}, pos, nil
	}
	if len(nodes) == 1 {
		return nodes[0], pos, nil
	}
	return sAnd{nodes}, pos, nil
}

func parseSearchOne(toks []string, pos int) (searchNode, int, error) {
	if pos >= len(toks) {
		return nil, pos, fmt.Errorf("unexpected end")
	}
	t := toks[pos]
	up := strings.ToUpper(t)
	switch up {
	case "(":
		n, np, err := parseSearchSeq(toks, pos+1)
		if err != nil {
			return nil, pos, err
		}
		if np >= len(toks) || toks[np] != ")" {
			return nil, pos, fmt.Errorf("missing )")
		}
		return n, np + 1, nil
	case "ALL":
		return sAll{}, pos + 1, nil
	case "SEEN":
		return sFlag{flag: "seen", want: true}, pos + 1, nil
	case "UNSEEN":
		return sFlag{flag: "seen", want: false}, pos + 1, nil
	case "ANSWERED":
		return sFlag{flag: "answered", want: true}, pos + 1, nil
	case "UNANSWERED":
		return sFlag{flag: "answered", want: false}, pos + 1, nil
	case "FLAGGED":
		return sFlag{flag: "flagged", want: true}, pos + 1, nil
	case "UNFLAGGED":
		return sFlag{flag: "flagged", want: false}, pos + 1, nil
	case "DELETED":
		return sFlag{flag: "deleted", want: true}, pos + 1, nil
	case "UNDELETED":
		return sFlag{flag: "deleted", want: false}, pos + 1, nil
	case "DRAFT":
		return sFlag{flag: "draft", want: true}, pos + 1, nil
	case "UNDRAFT":
		return sFlag{flag: "draft", want: false}, pos + 1, nil
	case "NEW", "RECENT":
		return sAll{}, pos + 1, nil // octo-mail has no \Recent; treat as ALL-ish no-op
	case "NOT":
		n, np, err := parseSearchOne(toks, pos+1)
		if err != nil {
			return nil, pos, err
		}
		return sNot{n}, np, nil
	case "OR":
		a, np, err := parseSearchOne(toks, pos+1)
		if err != nil {
			return nil, pos, err
		}
		b, np2, err := parseSearchOne(toks, np)
		if err != nil {
			return nil, pos, err
		}
		return sOr{a, b}, np2, nil
	case "FROM", "TO", "CC", "BCC", "SUBJECT":
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs arg", up)
		}
		return sHeader{name: strings.Title(strings.ToLower(up)), sub: toks[pos+1]}, pos + 2, nil
	case "HEADER":
		if pos+2 >= len(toks) {
			return nil, pos, fmt.Errorf("HEADER needs field+arg")
		}
		return sHeader{name: toks[pos+1], sub: toks[pos+2]}, pos + 3, nil
	case "BODY", "TEXT":
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs arg", up)
		}
		return sText{sub: toks[pos+1], headers: up == "TEXT"}, pos + 2, nil
	case "SINCE", "BEFORE", "ON":
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs date", up)
		}
		d, err := parseSearchDate(toks[pos+1])
		if err != nil {
			return nil, pos, err
		}
		return sDate{kind: up, date: d}, pos + 2, nil
	case "SAVEDSINCE", "SAVEDBEFORE", "SAVEDON":
		// RFC 8514: match on the mailbox save date rather than INTERNALDATE.
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs date", up)
		}
		d, err := parseSearchDate(toks[pos+1])
		if err != nil {
			return nil, pos, err
		}
		return sSavedDate{kind: strings.TrimPrefix(up, "SAVED"), date: d}, pos + 2, nil
	case "SAVEDATESUPPORTED":
		// RFC 8514: the server supports save dates on this mailbox → always true.
		return sAll{}, pos + 1, nil
	case "LARGER", "SMALLER":
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs size", up)
		}
		var n int64
		fmt.Sscan(toks[pos+1], &n)
		return sSize{larger: up == "LARGER", n: n}, pos + 2, nil
	case "OLDER", "YOUNGER":
		// RFC 5032 WITHIN: match on message age in seconds relative to now.
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("%s needs seconds", up)
		}
		var secs int64
		if _, err := fmt.Sscan(toks[pos+1], &secs); err != nil || secs < 0 {
			return nil, pos, fmt.Errorf("%s needs a non-negative integer", up)
		}
		return sWithin{older: up == "OLDER", secs: secs}, pos + 2, nil
	case "UID":
		if pos+1 >= len(toks) {
			return nil, pos, fmt.Errorf("UID needs set")
		}
		return sUIDSet{set: toks[pos+1]}, pos + 2, nil
	default:
		// SEARCHRES saved-result reference (RFC 5182): "$" matches the UIDs
		// saved by a prior SEARCH RETURN (SAVE).
		if t == "$" {
			return sSaved{}, pos + 1, nil
		}
		// A bare token that looks like a sequence set (e.g. "1:5,7").
		if isSeqSet(t) {
			return sSeqSet{set: t}, pos + 1, nil
		}
		return nil, pos, fmt.Errorf("unknown key %q", t)
	}
}

// --- criteria nodes ---

type sAll struct{}

func (sAll) match(*conn, store.Message, uint32, uint32) bool { return true }

type sAnd struct{ nodes []searchNode }

func (a sAnd) match(c *conn, m store.Message, seq, total uint32) bool {
	for _, n := range a.nodes {
		if !n.match(c, m, seq, total) {
			return false
		}
	}
	return true
}

type sOr struct{ a, b searchNode }

func (o sOr) match(c *conn, m store.Message, seq, total uint32) bool {
	return o.a.match(c, m, seq, total) || o.b.match(c, m, seq, total)
}

type sNot struct{ n searchNode }

func (s sNot) match(c *conn, m store.Message, seq, total uint32) bool {
	return !s.n.match(c, m, seq, total)
}

type sFlag struct {
	flag string
	want bool
}

func (f sFlag) match(_ *conn, m store.Message, _, _ uint32) bool {
	var v bool
	switch f.flag {
	case "seen":
		v = m.Seen
	case "answered":
		v = m.Answered
	case "flagged":
		v = m.Flagged
	case "deleted":
		v = m.Deleted
	case "draft":
		v = m.Draft
	}
	return v == f.want
}

type sSize struct {
	larger bool
	n      int64
}

func (s sSize) match(_ *conn, m store.Message, _, _ uint32) bool {
	if s.larger {
		return m.Size > s.n
	}
	return m.Size < s.n
}

type sDate struct {
	kind string // SINCE | BEFORE | ON
	date time.Time
}

func (s sDate) match(_ *conn, m store.Message, _, _ uint32) bool {
	md := m.Received.UTC().Truncate(24 * time.Hour)
	d := s.date.UTC().Truncate(24 * time.Hour)
	switch s.kind {
	case "SINCE":
		return !md.Before(d)
	case "BEFORE":
		return md.Before(d)
	case "ON":
		return md.Equal(d)
	}
	return false
}

// sSavedDate matches on the mailbox save date (RFC 8514 SAVEDSINCE/BEFORE/ON).
type sSavedDate struct {
	kind string // SINCE | BEFORE | ON (already stripped of the SAVED prefix)
	date time.Time
}

func (s sSavedDate) match(_ *conn, m store.Message, _, _ uint32) bool {
	md := m.SaveDate.UTC().Truncate(24 * time.Hour)
	d := s.date.UTC().Truncate(24 * time.Hour)
	switch s.kind {
	case "SINCE":
		return !md.Before(d)
	case "BEFORE":
		return md.Before(d)
	case "ON":
		return md.Equal(d)
	}
	return false
}

type sWithin struct {
	older bool  // OLDER = message age >= secs; YOUNGER = age <= secs
	secs  int64 // relative to now
}

func (s sWithin) match(_ *conn, m store.Message, _, _ uint32) bool {
	age := time.Since(m.Received)
	within := time.Duration(s.secs) * time.Second
	if s.older {
		return age >= within
	}
	return age <= within
}

type sHeader struct {
	name string
	sub  string
}

func (h sHeader) match(c *conn, m store.Message, _, _ uint32) bool {
	hdr := c.messageHeaderValue(m, h.name)
	return strings.Contains(strings.ToLower(hdr), strings.ToLower(h.sub))
}

type sText struct {
	sub     string
	headers bool // TEXT searches headers+body; BODY searches body only
}

func (t sText) match(c *conn, m store.Message, _, _ uint32) bool {
	// BODY/TEXT use the async fts projection (precomputed in cmdSearch). This
	// matches the design: full-text search is a projection, not a live scan.
	if hits, ok := c.ftsHits[strings.ToLower(t.sub)]; ok {
		return hits[m.UID]
	}
	// Fallback (should not happen): direct scan.
	full := c.messageBytes(m)
	hay := full
	if !t.headers {
		if i := strings.Index(full, "\r\n\r\n"); i >= 0 {
			hay = full[i+4:]
		}
	}
	return strings.Contains(strings.ToLower(hay), strings.ToLower(t.sub))
}

// collectTextTerms returns all BODY/TEXT search terms in the criteria tree, so
// their fts hit-sets can be precomputed once.
func collectTextTerms(n searchNode) []string {
	switch v := n.(type) {
	case sText:
		return []string{v.sub}
	case sNot:
		return collectTextTerms(v.n)
	case sOr:
		return append(collectTextTerms(v.a), collectTextTerms(v.b)...)
	case sAnd:
		var out []string
		for _, c := range v.nodes {
			out = append(out, collectTextTerms(c)...)
		}
		return out
	}
	return nil
}

type sUIDSet struct{ set string }

func (u sUIDSet) match(_ *conn, m store.Message, _, _ uint32) bool {
	return matchSet(u.set, uint32(m.UID))
}

// sSaved matches the "$" saved-result reference (RFC 5182 SEARCHRES): a message
// is in the set if its UID was saved by a prior SEARCH RETURN (SAVE).
type sSaved struct{}

func (sSaved) match(c *conn, m store.Message, _, _ uint32) bool {
	for _, uid := range c.savedSearch {
		if uid == m.UID {
			return true
		}
	}
	return false
}

type sSeqSet struct{ set string }

func (s sSeqSet) match(_ *conn, _ store.Message, seq, total uint32) bool {
	return matchSetStar(s.set, seq, total)
}

// --- helpers ---

func (c *conn) messageBytes(m store.Message) string {
	r := c.acc.MessageReader(m)
	data, _ := io.ReadAll(r)
	r.Close()
	return string(data)
}

// messageHeaderValue returns the (first) value of a header from the message.
func (c *conn) messageHeaderValue(m store.Message, name string) string {
	full := c.messageBytes(m)
	end := strings.Index(full, "\r\n\r\n")
	if end >= 0 {
		full = full[:end]
	}
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(full, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func parseSearchDate(s string) (time.Time, error) {
	// IMAP date: dd-Mon-yyyy (e.g. 01-Jul-2026).
	return time.Parse("02-Jan-2006", s)
}

func isSeqSet(s string) bool {
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9') && ch != ':' && ch != ',' && ch != '*' {
			return false
		}
	}
	return s != ""
}

// matchSet matches a numeric set like "1:5,7" against v (no '*').
func matchSet(set string, v uint32) bool {
	return matchSetStar(set, v, v)
}

// matchSetStar matches a set where '*' resolves to max.
func matchSetStar(set string, v, max uint32) bool {
	for _, part := range strings.Split(set, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a := parseSeqNum(lo, max)
		if !isRange {
			if a == v {
				return true
			}
			continue
		}
		b := parseSeqNum(hi, max)
		if a > b {
			a, b = b, a
		}
		if v >= a && v <= b {
			return true
		}
	}
	return false
}

func parseSeqNum(s string, max uint32) uint32 {
	if s == "*" {
		return max
	}
	var n uint32
	fmt.Sscan(s, &n)
	return n
}
