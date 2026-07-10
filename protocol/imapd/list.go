package imapd

import (
	"fmt"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdList implements LIST (RFC 3501) and LIST-EXTENDED (RFC 5258). Syntax:
//
//	LIST [ (selection-opts) ] reference (patterns | pattern) [ RETURN (return-opts) ]
//
// Selection options: SUBSCRIBED (only subscribed mailboxes), RECURSIVEMATCH.
// Return options: SUBSCRIBED (annotate \Subscribed), CHILDREN (\HasChildren /
// \HasNoChildren), SPECIAL-USE (annotate role), STATUS (...) (per-mailbox STATUS).
// The classic two-argument form (reference + single pattern) is a subset.
func (c *conn) cmdList(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}

	rest := strings.TrimSpace(args)

	// Optional selection options: a leading parenthesized list.
	selSubscribed := false
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			c.no(tag, "malformed selection options")
			return
		}
		for _, o := range strings.Fields(strings.ToUpper(rest[1:end])) {
			switch o {
			case "SUBSCRIBED":
				selSubscribed = true
			case "RECURSIVEMATCH":
				// Accepted; our matcher already returns parents of matches implicitly
				// via the pattern, so no extra behavior is required for the subset.
			}
		}
		rest = strings.TrimSpace(rest[end+1:])
	}

	// Optional trailing RETURN (opts).
	retSubscribed, retChildren, retSpecialUse := false, false, false
	var statusItems []string
	var metadataEntries []string
	if i := strings.LastIndex(strings.ToUpper(rest), "RETURN "); i >= 0 {
		ret := strings.TrimSpace(rest[i+len("RETURN "):])
		rest = strings.TrimSpace(rest[:i])
		ret = strings.TrimPrefix(ret, "(")
		ret = strings.TrimSuffix(ret, ")")
		// Extract a nested STATUS (...) before splitting the rest on spaces.
		if si := strings.Index(strings.ToUpper(ret), "STATUS"); si >= 0 {
			if lp := strings.IndexByte(ret[si:], '('); lp >= 0 {
				if rp := strings.IndexByte(ret[si+lp:], ')'); rp >= 0 {
					statusItems = strings.Fields(strings.ToUpper(ret[si+lp+1 : si+lp+rp]))
					ret = ret[:si] + ret[si+lp+rp+1:]
				}
			}
		}
		// Extract a nested METADATA (/entry ...) (RFC 9590). Entry names are
		// case-sensitive paths, so keep them verbatim (unlike STATUS items).
		if mi := strings.Index(strings.ToUpper(ret), "METADATA"); mi >= 0 {
			if lp := strings.IndexByte(ret[mi:], '('); lp >= 0 {
				if rp := strings.IndexByte(ret[mi+lp:], ')'); rp >= 0 {
					metadataEntries = strings.Fields(ret[mi+lp+1 : mi+lp+rp])
					ret = ret[:mi] + ret[mi+lp+rp+1:]
				}
			}
		}
		for _, o := range strings.Fields(strings.ToUpper(ret)) {
			switch o {
			case "SUBSCRIBED":
				retSubscribed = true
			case "CHILDREN":
				retChildren = true
			case "SPECIAL-USE":
				retSpecialUse = true
			}
		}
	}

	// Remaining: reference and one-or-more patterns. The reference is a prefix
	// prepended to each pattern; typically empty.
	refTok, patRest := cut(rest, " ")
	ref := unquote(strings.TrimSpace(refTok))
	patRest = strings.TrimSpace(patRest)
	var patterns []string
	if strings.HasPrefix(patRest, "(") {
		end := strings.IndexByte(patRest, ')')
		if end < 0 {
			c.no(tag, "malformed pattern list")
			return
		}
		for _, p := range splitQuotedFields(patRest[1:end]) {
			patterns = append(patterns, normalizeMailbox(ref+p))
		}
	} else {
		patterns = append(patterns, normalizeMailbox(ref+unquote(patRest)))
	}

	var mbs []store.Mailbox
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		var e error
		mbs, e = tx.QueryMailbox().List()
		return e
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}

	// Precompute which mailbox names have children (a mailbox X has children if
	// some other mailbox is named "X/...").
	hasChild := map[string]bool{}
	for _, a := range mbs {
		for _, b := range mbs {
			if a.ID != b.ID && strings.HasPrefix(b.Name, a.Name+"/") {
				hasChild[a.Name] = true
				break
			}
		}
	}

	for _, mb := range mbs {
		if !matchAnyPattern(patterns, mb.Name) {
			continue
		}
		if selSubscribed && !mb.Subscribed {
			continue
		}
		var flags []string
		if (retSubscribed || selSubscribed) && mb.Subscribed {
			flags = append(flags, `\Subscribed`)
		}
		if retChildren {
			if hasChild[mb.Name] {
				flags = append(flags, `\HasChildren`)
			} else {
				flags = append(flags, `\HasNoChildren`)
			}
		}
		// Special-use attributes are always reported (RFC 6154): clients rely on
		// them to locate Drafts/Sent/Junk/Trash/Archive regardless of RETURN opts.
		_ = retSpecialUse
		flags = append(flags, specialUseFlags(mb.SpecialUse)...)
		c.writef(`* LIST (%s) "/" %s`, strings.Join(flags, " "), quote(mb.Name))
		if len(statusItems) > 0 {
			c.emitStatus(mb.Name, statusItems)
		}
		if len(metadataEntries) > 0 {
			c.emitMetadata(mb, metadataEntries)
		}
	}
	c.ok(tag, "LIST completed")
}

// emitMetadata writes an untagged METADATA line for a mailbox as part of a LIST
// RETURN (METADATA (...)) response (RFC 9590), reusing the annotation store and
// the same value encoding as GETMETADATA.
func (c *conn) emitMetadata(mb store.Mailbox, entries []string) {
	anns, err := c.acc.AnnotationList(c.ctx, mb.ID, entries)
	if err != nil || len(anns) == 0 {
		return
	}
	var parts []string
	for _, a := range anns {
		parts = append(parts, quote(a.Key)+" "+metadataValue(a))
	}
	c.writef("* METADATA %s (%s)", quote(mb.Name), strings.Join(parts, " "))
}

// cmdLsub implements LSUB (RFC 3501): list subscribed mailboxes matching the
// pattern, emitting "* LSUB" lines. Superseded by LIST (SUBSCRIBED) but still
// used by older clients.
func (c *conn) cmdLsub(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	refTok, patTok := cut(strings.TrimSpace(args), " ")
	ref := unquote(strings.TrimSpace(refTok))
	pattern := ref + unquote(strings.TrimSpace(patTok))

	var mbs []store.Mailbox
	err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		var e error
		mbs, e = tx.QueryMailbox().List()
		return e
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	for _, mb := range mbs {
		if !mb.Subscribed || !matchPattern(pattern, mb.Name) {
			continue
		}
		c.writef(`* LSUB () "/" %s`, quote(mb.Name))
	}
	c.ok(tag, "LSUB completed")
}

// specialUseFlags maps a mailbox's special-use bits to IMAP attribute flags.
func specialUseFlags(su store.SpecialUse) []string {
	var out []string
	if su.Archive {
		out = append(out, `\Archive`)
	}
	if su.Draft {
		out = append(out, `\Drafts`)
	}
	if su.Junk {
		out = append(out, `\Junk`)
	}
	if su.Sent {
		out = append(out, `\Sent`)
	}
	if su.Trash {
		out = append(out, `\Trash`)
	}
	return out
}

// parseSpecialUse parses a space-separated list of special-use attribute flags
// (as in CREATE ... USE (\Sent \Drafts)) into a store.SpecialUse. Unknown flags
// are ignored. Inverse of specialUseFlags.
func parseSpecialUse(s string) store.SpecialUse {
	var su store.SpecialUse
	for _, f := range strings.Fields(s) {
		switch strings.ToLower(f) {
		case `\archive`:
			su.Archive = true
		case `\drafts`:
			su.Draft = true
		case `\junk`:
			su.Junk = true
		case `\sent`:
			su.Sent = true
		case `\trash`:
			su.Trash = true
		}
	}
	return su
}

// matchAnyPattern reports whether name matches any of the IMAP LIST patterns.
func matchAnyPattern(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchPattern(p, name) {
			return true
		}
	}
	return false
}

// matchPattern implements IMAP wildcard matching: '*' matches across hierarchy
// separators, '%' matches within a single level (not '/'). An empty pattern
// matches nothing; "*" matches everything.
func matchPattern(pat, name string) bool {
	// Case-insensitive for the INBOX root, case-sensitive otherwise; we compare
	// as-is since mailbox names are already normalized.
	return wildMatch(pat, name)
}

func wildMatch(pat, s string) bool {
	// Iterative backtracking matcher for '*' (any, incl. '/') and '%' (any except '/').
	pi, si := 0, 0
	starPi, starSi := -1, 0
	pctPi, pctSi := -1, 0
	for si < len(s) {
		if pi < len(pat) && (pat[pi] == s[si] || pat[pi] == '*' || pat[pi] == '%') {
			switch pat[pi] {
			case '*':
				starPi, starSi = pi, si
				pctPi = -1
				pi++
			case '%':
				pctPi, pctSi = pi, si
				starPi = -1 // '%' is more specific; remember it separately below
				pi++
			default:
				pi++
				si++
			}
			continue
		}
		if starPi >= 0 {
			pi = starPi + 1
			starSi++
			si = starSi
			continue
		}
		if pctPi >= 0 && s[si] != '/' {
			pi = pctPi + 1
			pctSi++
			si = pctSi
			continue
		}
		return false
	}
	for pi < len(pat) && (pat[pi] == '*' || pat[pi] == '%') {
		pi++
	}
	return pi == len(pat)
}

// splitQuotedFields splits a space-separated list that may contain quoted items.
func splitQuotedFields(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			out = append(out, s[i+1:j])
			i = j + 1
		} else {
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

// emitStatus writes an untagged STATUS line for a mailbox as part of a LIST
// RETURN (STATUS ...) response, reusing the same attribute logic as cmdStatus.
func (c *conn) emitStatus(name string, items []string) {
	var mb *store.Mailbox
	var totalSize int64
	var deleted int
	_ = c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
		m, err := c.acc.MailboxFind(tx, name)
		if err != nil || m == nil {
			return err
		}
		mb = m
		for _, it := range items {
			if it == "SIZE" || it == "DELETED" {
				msgs, e := tx.QueryMessage().FilterMailbox(m.ID).List()
				if e != nil {
					return e
				}
				for _, msg := range msgs {
					totalSize += msg.Size
					if msg.Deleted {
						deleted++
					}
				}
				break
			}
		}
		return nil
	})
	if mb == nil {
		return
	}
	var parts []string
	for _, it := range items {
		switch it {
		case "MESSAGES":
			parts = append(parts, fmt.Sprintf("MESSAGES %d", mb.Total))
		case "UIDNEXT":
			parts = append(parts, fmt.Sprintf("UIDNEXT %d", mb.UIDNext))
		case "UIDVALIDITY":
			parts = append(parts, fmt.Sprintf("UIDVALIDITY %d", mb.UIDValidity))
		case "UNSEEN":
			parts = append(parts, fmt.Sprintf("UNSEEN %d", mb.Unseen))
		case "HIGHESTMODSEQ":
			parts = append(parts, fmt.Sprintf("HIGHESTMODSEQ %d", mb.ModSeq))
		case "SIZE":
			parts = append(parts, fmt.Sprintf("SIZE %d", totalSize))
		case "DELETED":
			parts = append(parts, fmt.Sprintf("DELETED %d", deleted))
		case "MAILBOXID":
			parts = append(parts, fmt.Sprintf("MAILBOXID (%s)", mailboxObjectID(mb.ID)))
		}
	}
	c.writef("* STATUS %s (%s)", quote(mb.Name), strings.Join(parts, " "))
}
