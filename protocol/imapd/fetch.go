package imapd

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/message"
)

func strconvParseInt(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

// cmdFetch handles FETCH and UID FETCH. args: "<set> (<attrs>)". Supports the
// common attributes a client needs to read mail: FLAGS, UID, RFC822.SIZE,
// INTERNALDATE(min), ENVELOPE(min), BODY[]/RFC822 (full body from the blob).
func (c *conn) cmdFetch(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	setStr, attrStr := cut(strings.TrimSpace(args), " ")
	attrStr = strings.TrimSpace(attrStr)

	// Optional CONDSTORE modifier after the attribute list: "(...) (CHANGEDSINCE n)".
	// This is the elegant payoff: CHANGEDSINCE is a changelog replay — filter
	// messages whose modseq (their changelog offset) is greater than n.
	var changedSince int64 = -1
	if i := strings.LastIndex(strings.ToUpper(attrStr), "(CHANGEDSINCE"); i >= 0 {
		tail := attrStr[i:]
		attrStr = strings.TrimSpace(attrStr[:i])
		changedSince = parseChangedSince(tail)
	}
	attrStr = strings.TrimPrefix(attrStr, "(")
	attrStr = strings.TrimSuffix(attrStr, ")")
	attrs := parseFetchAttrs(attrStr)
	if changedSince >= 0 {
		attrs.modseq = true // CONDSTORE: MODSEQ is implicitly returned.
	}

	// Load the mailbox's messages in UID order (seq number = position+1). When
	// CHANGEDSINCE is set, the kernel filters by changelog offset directly.
	var msgs []store.Message
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		q := tx.QueryMessage().FilterMailbox(c.selected.ID)
		if changedSince >= 0 {
			q = q.FilterModSeqGreater(store.ModSeq(changedSince))
		}
		var e error
		msgs, e = q.SortUID().List()
		return e
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	var maxUID uint32
	if len(msgs) > 0 {
		maxUID = uint32(msgs[len(msgs)-1].UID)
	}

	var match func(uint32) bool
	if byUID {
		match = parseUIDSet(setStr, maxUID)
	} else {
		matchSeq := parseUIDSet(setStr, uint32(len(msgs))) // reuse: treat as seq set
		match = func(seq uint32) bool { return matchSeq(seq) }
	}

	// Count how many messages the set selects, to drive INPROGRESS goal reporting.
	total := 0
	for i, m := range msgs {
		if byUID {
			if match(uint32(m.UID)) {
				total++
			}
		} else if match(uint32(i + 1)) {
			total++
		}
	}
	done := 0
	for i, m := range msgs {
		seq := uint32(i + 1)
		var selected bool
		if byUID {
			selected = match(uint32(m.UID))
		} else {
			selected = match(seq)
		}
		if !selected {
			continue
		}
		c.writeFetch(seq, m, attrs, byUID)
		done++
		// INPROGRESS (RFC 9585): for a large fetch, emit periodic progress so the
		// client knows a long-running command is advancing. Every 100 messages.
		if total >= inprogressThreshold && done%100 == 0 && done < total {
			c.writef(`* OK [INPROGRESS (%s %d %d)] fetching`, qstr(tag), done, total)
		}
	}
	c.ok(tag, "FETCH completed")
}

// inprogressThreshold is the message count above which FETCH emits INPROGRESS
// progress updates.
const inprogressThreshold = 100

// cmdSearch handles SEARCH and UID SEARCH with a real criteria tree (RFC 3501
// §6.4.4): flags, dates (SINCE/BEFORE/ON via INTERNALDATE), FROM/TO/CC/SUBJECT/
// HEADER substring, BODY/TEXT, LARGER/SMALLER, UID sets, sequence sets, NOT, OR,
// and implicit AND. Evaluated per message; header/body criteria read the blob.
func (c *conn) cmdSearch(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	crit := strings.TrimSpace(args)

	// Optional ESEARCH RETURN clause (RFC 4731): "RETURN (MIN MAX ALL COUNT SAVE)".
	// When present, results are reported as an ESEARCH response; when absent, the
	// classic "* SEARCH" untagged response is used.
	var retOpts []string
	esearch := false
	if up := strings.ToUpper(crit); strings.HasPrefix(up, "RETURN ") {
		esearch = true
		rest := strings.TrimSpace(crit[len("RETURN "):])
		if !strings.HasPrefix(rest, "(") {
			c.no(tag, "malformed RETURN clause")
			return
		}
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			c.no(tag, "malformed RETURN clause")
			return
		}
		retOpts = strings.Fields(strings.ToUpper(rest[1:end]))
		crit = strings.TrimSpace(rest[end+1:])
	}

	// Skip an optional leading charset spec: "CHARSET UTF-8 ...".
	if up := strings.ToUpper(crit); strings.HasPrefix(up, "CHARSET ") {
		rest := crit[len("CHARSET "):]
		_, crit = cut(strings.TrimSpace(rest), " ")
		crit = strings.TrimSpace(crit)
	}

	toks := tokenizeSearch(crit)
	node, _, perr := parseSearchSeq(toks, 0)
	if perr != nil {
		c.no(tag, "unsupported SEARCH criteria: "+perr.Error())
		return
	}

	// Precompute FTS hit sets for any BODY/TEXT terms in the tree, so full-text
	// search uses the async fts projection (scalable, matches the projection design) rather than
	// a full blob scan. Non-text criteria evaluate directly per message.
	c.ftsHits = map[string]map[store.UID]bool{}
	for _, q := range collectTextTerms(node) {
		hits := map[store.UID]bool{}
		_ = c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
			ms, e := tx.QueryMessage().FilterMailbox(c.selected.ID).FilterFTS(q).List()
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
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		var e error
		allMsgs, e = tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
		return e
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}

	// Collect matches: string ids for the classic response, plus numeric values
	// for ESEARCH aggregates and the saved UID set.
	var ids []string
	var nums []uint32 // seq or uid, matching the response mode
	var matchedUIDs []store.UID
	for i, m := range allMsgs {
		seq := uint32(i + 1)
		if !node.match(c, m, seq, uint32(len(allMsgs))) {
			continue
		}
		matchedUIDs = append(matchedUIDs, m.UID)
		var v uint32
		if byUID {
			v = uint32(m.UID)
		} else {
			v = seq
		}
		nums = append(nums, v)
		ids = append(ids, strconv.FormatUint(uint64(v), 10))
	}

	if !esearch {
		if len(ids) > 0 {
			c.writef("* SEARCH %s", strings.Join(ids, " "))
		} else {
			c.writef("* SEARCH")
		}
		c.ok(tag, "SEARCH completed")
		return
	}

	// ESEARCH response (RFC 4731). SAVE stores the matched UIDs as the "$"
	// saved result; it does not itself produce a returned data item.
	save := false
	for _, o := range retOpts {
		if o == "SAVE" {
			save = true
		}
	}
	if save {
		c.savedSearch = matchedUIDs
	}
	// If no explicit return option (other than SAVE) is given, ALL is implied.
	wantMin, wantMax, wantAll, wantCount := false, false, false, false
	for _, o := range retOpts {
		switch o {
		case "MIN":
			wantMin = true
		case "MAX":
			wantMax = true
		case "ALL":
			wantAll = true
		case "COUNT":
			wantCount = true
		}
	}
	if !wantMin && !wantMax && !wantAll && !wantCount && !save {
		wantAll = true
	}

	parts := []string{fmt.Sprintf("(TAG %s)", quote(tag))}
	if byUID {
		parts = append(parts, "UID")
	}
	if wantMin && len(nums) > 0 {
		parts = append(parts, fmt.Sprintf("MIN %d", nums[0]))
	}
	if wantMax && len(nums) > 0 {
		parts = append(parts, fmt.Sprintf("MAX %d", nums[len(nums)-1]))
	}
	if wantCount {
		parts = append(parts, fmt.Sprintf("COUNT %d", len(nums)))
	}
	if wantAll && len(nums) > 0 {
		parts = append(parts, fmt.Sprintf("ALL %s", compressUIDList(ids)))
	}
	c.writef("* ESEARCH %s", strings.Join(parts, " "))
	c.ok(tag, "SEARCH completed")
}

type fetchReq struct {
	flags, uid, size, envelope, internaldate bool
	savedate                                 bool          // SAVEDATE (RFC 8514)
	preview                                  bool          // PREVIEW (RFC 8970)
	emailid, threadid                        bool          // OBJECTID (RFC 8474)
	modseq                                   bool          // CONDSTORE MODSEQ
	bodystructure                            bool          // BODYSTRUCTURE
	sections                                 []bodySection // BODY[...] parts requested
}

// bodySection is one requested BODY[...] item: the raw section spec (e.g. "",
// "HEADER", "TEXT", "HEADER.FIELDS (From To)"), whether it was BODY.PEEK (no
// implicit \Seen), and an optional <offset.count> partial range.
type bodySection struct {
	spec       string
	peek       bool
	hasPartial bool
	partOff    int64
	partCount  int64
	raw        string // the exact token as sent, echoed back in the response
	binary     bool   // BINARY[...] (RFC 3516): decode the part's content-transfer-encoding
	binarySize bool   // BINARY.SIZE[...]: return only the decoded octet count
}

// parseChangedSince extracts n from a "(CHANGEDSINCE n ...)" modifier, or -1.
func parseChangedSince(s string) int64 {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	f := strings.Fields(s)
	if len(f) >= 2 && strings.EqualFold(f[0], "CHANGEDSINCE") {
		if n, err := strconvParseInt(f[1]); err == nil {
			return n
		}
	}
	return -1
}

func parseFetchAttrs(s string) fetchReq {
	var r fetchReq
	for _, a := range splitFetchAttrs(s) {
		up := strings.ToUpper(a)
		switch up {
		case "FLAGS":
			r.flags = true
		case "UID":
			r.uid = true
		case "RFC822.SIZE":
			r.size = true
		case "ENVELOPE":
			r.envelope = true
		case "INTERNALDATE":
			r.internaldate = true
		case "SAVEDATE":
			r.savedate = true
		case "PREVIEW":
			r.preview = true
		case "EMAILID":
			r.emailid = true
		case "THREADID":
			r.threadid = true
		case "BODYSTRUCTURE", "BODY": // bare BODY == BODYSTRUCTURE (non-extensible)
			r.bodystructure = true
		case "RFC822":
			r.sections = append(r.sections, bodySection{spec: "", raw: "RFC822"})
		case "RFC822.HEADER":
			r.sections = append(r.sections, bodySection{spec: "HEADER", raw: "RFC822.HEADER"})
		case "RFC822.TEXT":
			r.sections = append(r.sections, bodySection{spec: "TEXT", raw: "RFC822.TEXT"})
		case "ALL", "FULL":
			r.flags, r.uid, r.size, r.envelope, r.internaldate = true, true, true, true, true
			if up == "FULL" {
				r.sections = append(r.sections, bodySection{spec: "", raw: "BODY[]"})
			}
		case "FAST":
			r.flags, r.size, r.internaldate = true, true, true
		default:
			// PREVIEW (LAZY) / PREVIEW (...) — a single token whose parens didn't
			// split. Any PREVIEW modifier maps to the same on-demand computation.
			if strings.HasPrefix(up, "PREVIEW") {
				r.preview = true
				continue
			}
			// BODY[...]/BODY.PEEK[...] with optional <partial>.
			if sec, ok := parseBodySection(a); ok {
				r.sections = append(r.sections, sec)
			}
		}
	}
	return r
}

// splitFetchAttrs splits an attribute list on spaces but keeps "[...]" and
// "(...)" groups (and "<...>" partials) intact.
func splitFetchAttrs(s string) []string {
	var out []string
	depthB, depthP, depthA := 0, 0, 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depthB++
		case ']':
			if depthB > 0 {
				depthB--
			}
		case '(':
			depthP++
		case ')':
			if depthP > 0 {
				depthP--
			}
		case '<':
			depthA++
		case '>':
			if depthA > 0 {
				depthA--
			}
		case ' ':
			if depthB == 0 && depthP == 0 && depthA == 0 {
				if i > start {
					out = append(out, s[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// parseBodySection parses "BODY[<spec>]" or "BODY.PEEK[<spec>]" with an optional
// "<off.count>" partial suffix.
func parseBodySection(a string) (bodySection, bool) {
	raw := a
	up := strings.ToUpper(a)
	peek := false
	binary := false
	binarySize := false
	switch {
	case strings.HasPrefix(up, "BODY.PEEK["):
		peek = true
		a = a[len("BODY.PEEK["):]
	case strings.HasPrefix(up, "BODY["):
		a = a[len("BODY["):]
	case strings.HasPrefix(up, "BINARY.PEEK["):
		peek, binary = true, true
		a = a[len("BINARY.PEEK["):]
	case strings.HasPrefix(up, "BINARY.SIZE["):
		binary, binarySize = true, true
		a = a[len("BINARY.SIZE["):]
	case strings.HasPrefix(up, "BINARY["):
		binary = true
		a = a[len("BINARY["):]
	default:
		return bodySection{}, false
	}
	end := strings.IndexByte(a, ']')
	if end < 0 {
		return bodySection{}, false
	}
	spec := a[:end]
	rest := a[end+1:]
	sec := bodySection{spec: strings.ToUpper(strings.TrimSpace(spec)), peek: peek, raw: raw, binary: binary, binarySize: binarySize}
	// Preserve original-case for HEADER.FIELDS field names (spec kept upper for
	// dispatch; field names re-parsed from raw when needed).
	if strings.HasPrefix(rest, "<") {
		inner := strings.TrimSuffix(strings.TrimPrefix(rest, "<"), ">")
		off, cnt, ok := parsePartial(inner)
		if ok {
			sec.hasPartial = true
			sec.partOff = off
			sec.partCount = cnt
		}
	}
	return sec, true
}

func parsePartial(s string) (off, count int64, ok bool) {
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		if _, e := fmt.Sscan(s, &off); e != nil {
			return 0, 0, false
		}
		return off, -1, true
	}
	if _, e := fmt.Sscan(s[:dot], &off); e != nil {
		return 0, 0, false
	}
	if _, e := fmt.Sscan(s[dot+1:], &count); e != nil {
		return 0, 0, false
	}
	return off, count, true
}

func (c *conn) writeFetch(seq uint32, m store.Message, r fetchReq, byUID bool) {
	// Read + parse the message at most once: ENVELOPE, BODYSTRUCTURE, and body
	// sections all derive from the same bytes/parse.
	var full []byte
	var part *message.Part
	if r.envelope || r.bodystructure || r.preview || len(r.sections) > 0 {
		full = []byte(c.messageBytes(m))
		p, err := message.EnsurePart(nil, false, bytes.NewReader(full), int64(len(full)))
		if err == nil || len(p.Parts) > 0 || p.MediaType != "" || p.Envelope != nil {
			part = &p
		}
	}

	var parts []string
	// UID is always returned for UID FETCH (RFC requirement).
	if r.uid || byUID {
		parts = append(parts, fmt.Sprintf("UID %d", m.UID))
	}
	if r.flags {
		parts = append(parts, "FLAGS ("+strings.Join(flagStrings(m), " ")+")")
	}
	if r.size {
		parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", m.Size))
	}
	if r.modseq {
		parts = append(parts, fmt.Sprintf("MODSEQ (%d)", m.ModSeq))
	}
	if r.envelope && part != nil {
		if env := buildEnvelope(part); env != "" {
			parts = append(parts, "ENVELOPE "+env)
		}
	}
	if r.internaldate {
		id := m.Received
		if id.IsZero() {
			id = time.Unix(0, 0).UTC()
		}
		parts = append(parts, `INTERNALDATE "`+id.Format("02-Jan-2006 15:04:05 -0700")+`"`)
	}
	if r.savedate {
		// SAVEDATE (RFC 8514): the time the message was saved into this mailbox.
		// NIL when unknown (never, for our rows — every insert stamps save_date).
		if m.SaveDate.IsZero() {
			parts = append(parts, "SAVEDATE NIL")
		} else {
			parts = append(parts, `SAVEDATE "`+m.SaveDate.Format("02-Jan-2006 15:04:05 -0700")+`"`)
		}
	}
	if r.preview {
		// PREVIEW (RFC 8970): a short text abstract of the message, emitted as a
		// string. Derived from the first text/* part; empty → NIL.
		pv := previewText(full, part)
		if pv == "" {
			parts = append(parts, "PREVIEW NIL")
		} else {
			parts = append(parts, "PREVIEW "+qstr(pv))
		}
	}
	if r.emailid {
		// OBJECTID EMAILID (RFC 8474): the stable email identity (JMAP-consistent).
		parts = append(parts, "EMAILID ("+emailObjectID(m)+")")
	}
	if r.threadid {
		// OBJECTID THREADID: the thread identity, or NIL when not yet threaded.
		if tid := threadObjectID(m); tid != "" {
			parts = append(parts, "THREADID ("+tid+")")
		} else {
			parts = append(parts, "THREADID NIL")
		}
	}
	if r.bodystructure && part != nil {
		if bs := renderBodyStructure(part); bs != "" {
			parts = append(parts, "BODYSTRUCTURE "+bs)
		}
	}

	// Body sections: each renders a literal (or, for BINARY.SIZE, a number).
	type sectOut struct {
		header  string // e.g. "BODY[HEADER]", "BINARY[1]", "BINARY.SIZE[1]"
		data    []byte
		sizeNum bool // render as " <header> <n>" instead of a literal
	}
	var sects []sectOut
	if len(r.sections) > 0 {
		for _, sec := range r.sections {
			data := extractSection(full, sec)
			hdr := normalizeSectionKey(sec)
			if sec.binarySize {
				sects = append(sects, sectOut{header: hdr, data: []byte(strconv.Itoa(len(data))), sizeNum: true})
				continue
			}
			if sec.hasPartial {
				hdr = fmt.Sprintf("%s<%d>", hdr, sec.partOff)
			}
			sects = append(sects, sectOut{header: hdr, data: data})
		}
	}

	// Compose the response. Under UIDONLY (RFC 9586) the untagged form is
	// "* UIDFETCH <uid> (...)"; otherwise the classic "* <seq> FETCH (...)".
	// Hold the write lock for the whole multi-write response so a concurrent
	// NOTIFY pusher (which writes via writef under the same lock) cannot splice
	// its output into the middle of this FETCH literal.
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.uidonly {
		fmt.Fprintf(c.w, "* UIDFETCH %d (%s", m.UID, strings.Join(parts, " "))
	} else {
		fmt.Fprintf(c.w, "* %d FETCH (%s", seq, strings.Join(parts, " "))
	}
	sep := ""
	if len(parts) > 0 {
		sep = " "
	}
	for _, so := range sects {
		if so.sizeNum {
			fmt.Fprintf(c.w, "%s%s %s", sep, so.header, string(so.data))
			sep = " "
			continue
		}
		fmt.Fprintf(c.w, "%s%s {%d}\r\n", sep, so.header, len(so.data))
		c.w.Write(so.data)
		sep = " "
	}
	fmt.Fprint(c.w, ")\r\n")
}

// extractSection returns the requested body section bytes, applying any partial.
func extractSection(full []byte, sec bodySection) []byte {
	// BINARY[...] (RFC 3516): return the part's body decoded from its
	// content-transfer-encoding (base64/quoted-printable → raw octets).
	if sec.binary {
		return applyPartial(decodeBinaryPart(full, sec.spec), sec)
	}
	var out []byte
	hdrEnd := indexHeaderEnd(full)
	switch {
	case sec.spec == "":
		out = full
	case sec.spec == "HEADER":
		out = full[:hdrEnd]
	case sec.spec == "TEXT":
		if hdrEnd <= len(full) {
			out = full[hdrEnd:]
		}
	case strings.HasPrefix(sec.spec, "HEADER.FIELDS.NOT"):
		out = extractHeaderFields(full[:hdrEnd], sec.raw, true)
	case strings.HasPrefix(sec.spec, "HEADER.FIELDS"):
		out = extractHeaderFields(full[:hdrEnd], sec.raw, false)
	default:
		if isNumericSection(sec.spec) {
			out = extractNumericPart(full, sec.spec)
		} else {
			out = full // unknown section: return whole (best-effort)
		}
	}
	return applyPartial(out, sec)
}

// applyPartial applies a BODY[...]<off.count> partial range to a section's bytes,
// clamping the offset and count to the available length.
func applyPartial(out []byte, sec bodySection) []byte {
	if !sec.hasPartial {
		return out
	}
	off := sec.partOff
	if off > int64(len(out)) {
		off = int64(len(out))
	}
	out = out[off:]
	if sec.partCount >= 0 && sec.partCount < int64(len(out)) {
		out = out[:sec.partCount]
	}
	return out
}

// indexHeaderEnd returns the offset just past the header/body separator.
func indexHeaderEnd(full []byte) int {
	if i := strings.Index(string(full), "\r\n\r\n"); i >= 0 {
		return i + 4
	}
	return len(full)
}

// isNumericSection reports whether spec is a MIME part path like "1", "1.2",
// "1.MIME", "1.HEADER", "1.TEXT".
func isNumericSection(spec string) bool {
	return len(spec) > 0 && spec[0] >= '1' && spec[0] <= '9'
}

// extractNumericPart resolves a numbered MIME section (e.g. "1", "1.2",
// "2.MIME", "1.HEADER", "1.TEXT") against the parsed message tree.
func extractNumericPart(full []byte, spec string) []byte {
	part, err := message.EnsurePart(nil, false, bytes.NewReader(full), int64(len(full)))
	if err != nil && len(part.Parts) == 0 {
		return nil
	}
	// Split trailing keyword (MIME/HEADER/TEXT) from the numeric path.
	nums := spec
	suffix := ""
	for _, kw := range []string{".MIME", ".HEADER", ".TEXT"} {
		if strings.HasSuffix(strings.ToUpper(spec), kw) {
			suffix = kw[1:]
			nums = spec[:len(spec)-len(kw)]
			break
		}
	}
	p := &part
	for _, seg := range strings.Split(nums, ".") {
		idx := 0
		fmt.Sscan(seg, &idx)
		if idx < 1 || idx > len(p.Parts) {
			// Single-part message: "1" refers to the whole part's body.
			if len(p.Parts) == 0 && seg == nums {
				break
			}
			return nil
		}
		p = &p.Parts[idx-1]
	}
	switch suffix {
	case "MIME", "HEADER":
		if p.BodyOffset > p.HeaderOffset && p.HeaderOffset >= 0 {
			return sliceRange(full, p.HeaderOffset, p.BodyOffset)
		}
		return nil
	default: // body ("TEXT" or bare numeric)
		if p.EndOffset > p.BodyOffset && p.BodyOffset >= 0 {
			return sliceRange(full, p.BodyOffset, p.EndOffset)
		}
	}
	return nil
}

// decodeBinaryPart resolves a MIME part (empty spec = the whole message's single
// body; numeric = that part) and returns its body decoded from its
// content-transfer-encoding, via the Part.Reader (RFC 3516 BINARY).
func decodeBinaryPart(full []byte, spec string) []byte {
	part, err := message.EnsurePart(nil, false, bytes.NewReader(full), int64(len(full)))
	if err != nil && len(part.Parts) == 0 && part.MediaType == "" {
		return nil
	}
	p := &part
	if spec != "" {
		for _, seg := range strings.Split(spec, ".") {
			idx := 0
			fmt.Sscan(seg, &idx)
			if idx < 1 || idx > len(p.Parts) {
				if len(p.Parts) == 0 && seg == spec {
					break // single-part: "1" is the whole body
				}
				return nil
			}
			p = &p.Parts[idx-1]
		}
	}
	r := p.Reader()
	if r == nil {
		return nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	return data
}

func sliceRange(b []byte, lo, hi int64) []byte {
	if lo < 0 || hi > int64(len(b)) || lo > hi {
		return nil
	}
	return b[lo:hi]
}

// extractHeaderFields returns only the named header lines (or all but those, if
// exclude). fieldsRaw is the original "BODY[HEADER.FIELDS (From To)]" token.
func extractHeaderFields(header []byte, fieldsRaw string, exclude bool) []byte {
	lp := strings.IndexByte(fieldsRaw, '(')
	rp := strings.LastIndexByte(fieldsRaw, ')')
	if lp < 0 || rp <= lp {
		return header
	}
	want := map[string]bool{}
	for _, f := range strings.Fields(fieldsRaw[lp+1 : rp]) {
		want[strings.ToLower(f)] = true
	}
	var b strings.Builder
	for _, line := range strings.Split(string(header), "\r\n") {
		if line == "" {
			continue
		}
		name := line
		if i := strings.IndexByte(line, ':'); i >= 0 {
			name = line[:i]
		}
		in := want[strings.ToLower(strings.TrimSpace(name))]
		if in != exclude {
			b.WriteString(line + "\r\n")
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// normalizeSectionKey renders the response key for a section (BODY[...]).
func normalizeSectionKey(sec bodySection) string {
	// RFC822 aliases still echo BODY[...] per common server behavior; keep raw
	// BODY[...] form, but for RFC822* raw tokens map to the section.
	up := strings.ToUpper(sec.raw)
	switch {
	case up == "RFC822":
		return "BODY[]"
	case up == "RFC822.HEADER":
		return "BODY[HEADER]"
	case up == "RFC822.TEXT":
		return "BODY[TEXT]"
	}
	// Strip .PEEK from the echoed key (RFC: response is BODY[...], never PEEK).
	key := sec.raw
	if i := strings.IndexByte(key, '<'); i >= 0 {
		key = key[:i] // drop partial suffix; re-added by caller
	}
	key = strings.Replace(key, "BODY.PEEK[", "BODY[", 1)
	key = strings.Replace(key, "BINARY.PEEK[", "BINARY[", 1)
	return key
}

// renderBodyStructure produces the IMAP BODYSTRUCTURE token for a part.
func renderBodyStructure(p *message.Part) string {
	if len(p.Parts) > 0 {
		// multipart: (child1 child2 ... "SUBTYPE")
		var b strings.Builder
		b.WriteString("(")
		for i := range p.Parts {
			b.WriteString(renderBodyStructure(&p.Parts[i]))
		}
		sub := p.MediaSubType
		if sub == "" {
			sub = "MIXED"
		}
		b.WriteString(" " + qstr(sub) + ")")
		return b.String()
	}
	mt := p.MediaType
	if mt == "" {
		mt = "TEXT"
	}
	st := p.MediaSubType
	if st == "" {
		st = "PLAIN"
	}
	// (type subtype (params) id description encoding size [lines])
	enc := "7BIT"
	size := p.DecodedSize
	body := fmt.Sprintf("(%s %s NIL NIL NIL %s %d", qstr(mt), qstr(st), qstr(enc), size)
	if strings.EqualFold(mt, "TEXT") {
		body += fmt.Sprintf(" %d", p.RawLineCount)
	}
	body += ")"
	return body
}

// buildEnvelope renders an IMAP ENVELOPE structure (RFC 3501 §7.4.2) from an
// already-parsed message part: (date subject from sender reply-to to cc bcc
// in-reply-to message-id). Address lists are ((name adl mailbox host) ...) or
// NIL. Returns "" when the part has no parsed envelope.
func buildEnvelope(part *message.Part) string {
	if part == nil || part.Envelope == nil {
		return ""
	}
	env := part.Envelope
	addrList := func(as []message.Address) string {
		if len(as) == 0 {
			return "NIL"
		}
		var b strings.Builder
		b.WriteString("(")
		for _, a := range as {
			b.WriteString("(" + nstr(a.Name) + " NIL " + nstr(a.User) + " " + nstr(a.Host) + ")")
		}
		b.WriteString(")")
		return b.String()
	}
	date := "NIL"
	if !env.Date.IsZero() {
		date = qstr(env.Date.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	}
	return "(" + date + " " + nstr(env.Subject) + " " +
		addrList(env.From) + " " + addrList(env.Sender) + " " + addrList(env.ReplyTo) + " " +
		addrList(env.To) + " " + addrList(env.CC) + " " + addrList(env.BCC) + " " +
		nstr(env.InReplyTo) + " " + nstr(env.MessageID) + ")"
}

// nstr renders an IMAP nstring: NIL for empty, else a quoted string.
func nstr(s string) string {
	if s == "" {
		return "NIL"
	}
	return qstr(s)
}

// previewText builds an RFC 8970 PREVIEW: a short plain-text abstract of the
// message. It prefers the first text/* body part (decoded via the parsed part
// tree); if parsing yields nothing it falls back to the raw body after the
// header. Whitespace is collapsed and the result capped at 200 characters.
func previewText(full []byte, part *message.Part) string {
	var body string
	if part != nil {
		body = firstTextPart(part)
	}
	if body == "" {
		s := string(full)
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			body = s[i+4:]
		}
	}
	// Collapse all runs of whitespace (incl. CR/LF/control) into single spaces so
	// the result is a valid one-line IMAP quoted string.
	body = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, body)
	body = strings.Join(strings.Fields(body), " ")
	if len(body) > 200 {
		// Cap at 200 runes (not bytes) to avoid splitting a UTF-8 sequence.
		rs := []rune(body)
		if len(rs) > 200 {
			rs = rs[:200]
		}
		body = string(rs)
	}
	return body
}

// firstTextPart returns the decoded body of the first text/* leaf part, or "".
func firstTextPart(p *message.Part) string {
	if len(p.Parts) > 0 {
		for i := range p.Parts {
			if s := firstTextPart(&p.Parts[i]); s != "" {
				return s
			}
		}
		return ""
	}
	if p.MediaType != "" && !strings.EqualFold(p.MediaType, "TEXT") {
		return ""
	}
	r := p.Reader()
	if r == nil {
		return ""
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

func qstr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func flagStrings(m store.Message) []string {
	return flagsToStrings(m.Flags, m.Keywords)
}
