package imapd

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/message"
)

// cmdSort implements SORT and UID SORT (RFC 5256): "(sort-keys) charset
// search-criteria". Messages matching the criteria are ordered by the sort keys
// (ARRIVAL, DATE, FROM, TO, CC, SUBJECT, SIZE, with REVERSE inverting the next
// key) and returned as an "* SORT" list of seq numbers or UIDs.
func (c *conn) cmdSort(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	rest := strings.TrimSpace(args)
	if !strings.HasPrefix(rest, "(") {
		c.no(tag, "SORT requires a sort-key list")
		return
	}
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		c.no(tag, "malformed sort-key list")
		return
	}
	keys := parseSortKeys(rest[1:end])
	rest = strings.TrimSpace(rest[end+1:])

	// Next token is the charset (e.g. UTF-8); skip it.
	_, crit := cut(rest, " ")
	crit = strings.TrimSpace(crit)

	msgs, ok := c.searchMatches(tag, crit)
	if !ok {
		return
	}

	// Parse the envelope once per matched message for sort-key extraction.
	type row struct {
		seq uint32
		m   store.Message
		env *message.Envelope
	}
	rows := make([]row, len(msgs))
	for i, mm := range msgs {
		rows[i] = row{seq: mm.seq, m: mm.m, env: c.envelopeOf(mm.m)}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		return lessBySortKeys(keys, rows[i].m, rows[i].env, rows[j].m, rows[j].env)
	})

	var ids []string
	for _, r := range rows {
		if byUID {
			ids = append(ids, strconv.FormatUint(uint64(r.m.UID), 10))
		} else {
			ids = append(ids, strconv.FormatUint(uint64(r.seq), 10))
		}
	}
	if len(ids) > 0 {
		c.writef("* SORT %s", strings.Join(ids, " "))
	} else {
		c.writef("* SORT")
	}
	c.ok(tag, "SORT completed")
}

type sortKey struct {
	field   string // ARRIVAL DATE FROM TO CC SUBJECT SIZE
	reverse bool
}

func parseSortKeys(s string) []sortKey {
	var keys []sortKey
	toks := strings.Fields(strings.ToUpper(s))
	reverse := false
	for _, t := range toks {
		if t == "REVERSE" {
			reverse = true
			continue
		}
		keys = append(keys, sortKey{field: t, reverse: reverse})
		reverse = false
	}
	return keys
}

// lessBySortKeys compares two messages by the ordered sort keys.
func lessBySortKeys(keys []sortKey, ma store.Message, ea *message.Envelope, mb store.Message, eb *message.Envelope) bool {
	for _, k := range keys {
		cmp := compareSortField(k.field, ma, ea, mb, eb)
		if k.reverse {
			cmp = -cmp
		}
		if cmp != 0 {
			return cmp < 0
		}
	}
	// Tie-break by UID for a stable, deterministic order.
	return ma.UID < mb.UID
}

func compareSortField(field string, ma store.Message, ea *message.Envelope, mb store.Message, eb *message.Envelope) int {
	switch field {
	case "ARRIVAL":
		return cmpTime(ma.Received, mb.Received)
	case "DATE":
		return cmpTime(envDate(ea), envDate(eb))
	case "SIZE":
		return cmpInt64(ma.Size, mb.Size)
	case "SUBJECT":
		return strings.Compare(baseSubject(envSubject(ea)), baseSubject(envSubject(eb)))
	case "FROM":
		return strings.Compare(firstAddr(addrsOf(ea, "from")), firstAddr(addrsOf(eb, "from")))
	case "TO":
		return strings.Compare(firstAddr(addrsOf(ea, "to")), firstAddr(addrsOf(eb, "to")))
	case "CC":
		return strings.Compare(firstAddr(addrsOf(ea, "cc")), firstAddr(addrsOf(eb, "cc")))
	}
	return 0
}

// envelopeOf parses a message and returns its envelope, or nil on parse failure.
func (c *conn) envelopeOf(m store.Message) *message.Envelope {
	full := []byte(c.messageBytes(m))
	p, err := message.EnsurePart(nil, false, bytes.NewReader(full), int64(len(full)))
	if err != nil && p.Envelope == nil {
		return nil
	}
	return p.Envelope
}

func envDate(e *message.Envelope) time.Time {
	if e == nil {
		return time.Time{}
	}
	return e.Date
}

func envSubject(e *message.Envelope) string {
	if e == nil {
		return ""
	}
	return e.Subject
}

func addrsOf(e *message.Envelope, which string) []message.Address {
	if e == nil {
		return nil
	}
	switch which {
	case "from":
		return e.From
	case "to":
		return e.To
	case "cc":
		return e.CC
	}
	return nil
}

func firstAddr(as []message.Address) string {
	if len(as) == 0 {
		return ""
	}
	return strings.ToLower(as[0].User + "@" + as[0].Host)
}

// baseSubject strips a leading "Re:"/"Fwd:" run for SUBJECT sort and
// ORDEREDSUBJECT threading (RFC 5256 §2.1, simplified).
func baseSubject(s string) string {
	s = strings.TrimSpace(s)
	for {
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, "re:"):
			s = strings.TrimSpace(s[3:])
		case strings.HasPrefix(low, "fwd:"):
			s = strings.TrimSpace(s[4:])
		case strings.HasPrefix(low, "fw:"):
			s = strings.TrimSpace(s[3:])
		default:
			return strings.ToLower(s)
		}
	}
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	}
	return 0
}

// matchedMsg is one message that satisfied a SEARCH/SORT/THREAD criteria tree,
// with its 1-based sequence number.
type matchedMsg struct {
	seq uint32
	m   store.Message
}

// searchMatches parses a search criteria string, evaluates it against the
// selected mailbox, and returns the matching messages in UID order. It handles
// the FTS precomputation and reports errors to the client (returning ok=false).
// Shared by SEARCH, SORT, and THREAD.
func (c *conn) searchMatches(tag, crit string) ([]matchedMsg, bool) {
	return c.searchMatchesIn(tag, c.selected, crit)
}

// searchMatchesIn is like searchMatches but against an explicit mailbox, used by
// MULTISEARCH (ESEARCH IN) which searches mailboxes other than the selected one.
func (c *conn) searchMatchesIn(tag string, mb *store.Mailbox, crit string) ([]matchedMsg, bool) {
	// Skip an optional leading charset spec (SORT strips it already; SEARCH may not).
	if up := strings.ToUpper(crit); strings.HasPrefix(up, "CHARSET ") {
		_, crit = cut(strings.TrimSpace(crit[len("CHARSET "):]), " ")
		crit = strings.TrimSpace(crit)
	}
	if crit == "" {
		crit = "ALL"
	}
	toks := tokenizeSearch(crit)
	node, _, perr := parseSearchSeq(toks, 0)
	if perr != nil {
		c.no(tag, "unsupported criteria: "+perr.Error())
		return nil, false
	}

	c.ftsHits = map[string]map[store.UID]bool{}
	for _, q := range collectTextTerms(node) {
		hits := map[store.UID]bool{}
		_ = c.acc.Tx(c.ctx, func(tx store.Tx) error {
			ms, e := tx.QueryMessage().FilterMailbox(mb.ID).FilterFTS(q).List()
			if e != nil {
				return e
			}
			for _, mm := range ms {
				hits[mm.UID] = true
			}
			return nil
		})
		c.ftsHits[strings.ToLower(q)] = hits
	}
	defer func() { c.ftsHits = nil }()

	var allMsgs []store.Message
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		var e error
		allMsgs, e = tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		return e
	})
	if err != nil {
		c.no(tag, err.Error())
		return nil, false
	}
	var out []matchedMsg
	for i, m := range allMsgs {
		seq := uint32(i + 1)
		if node.match(c, m, seq, uint32(len(allMsgs))) {
			out = append(out, matchedMsg{seq: seq, m: m})
		}
	}
	return out, true
}
