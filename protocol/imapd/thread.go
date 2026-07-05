package imapd

import (
	"sort"
	"strconv"
	"strings"
)

// cmdThread implements THREAD and UID THREAD (RFC 5256): "algorithm charset
// search-criteria". Two algorithms are supported: REFERENCES (group by the
// change-log thread_id projection, which folds Message-ID/In-Reply-To/References)
// and ORDEREDSUBJECT (group by base subject). The result is an "* THREAD" list
// of nested parenthesized message groups.
func (c *conn) cmdThread(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	algo, rest := cut(strings.TrimSpace(args), " ")
	algo = strings.ToUpper(strings.TrimSpace(algo))
	rest = strings.TrimSpace(rest)
	// Next token is the charset; skip it.
	_, crit := cut(rest, " ")
	crit = strings.TrimSpace(crit)

	msgs, ok := c.searchMatches(tag, crit)
	if !ok {
		return
	}

	// Value to report for a message (seq or uid).
	idOf := func(mm matchedMsg) uint32 {
		if byUID {
			return uint32(mm.m.UID)
		}
		return mm.seq
	}

	// Group messages into threads.
	type group struct {
		key     string
		members []matchedMsg
	}
	order := []string{}
	groups := map[string]*group{}
	addTo := func(key string, mm matchedMsg) {
		g, ok := groups[key]
		if !ok {
			g = &group{key: key}
			groups[key] = g
			order = append(order, key)
		}
		g.members = append(g.members, mm)
	}

	for _, mm := range msgs {
		var key string
		if algo == "ORDEREDSUBJECT" {
			key = "s:" + baseSubject(envSubject(c.envelopeOf(mm.m)))
		} else {
			// REFERENCES: use the thread_id projection. Fall back to the message's
			// own id when unthreaded (thread_id == 0).
			if mm.m.ThreadID != 0 {
				key = "t:" + strconv.FormatInt(mm.m.ThreadID, 10)
			} else {
				key = "m:" + strconv.FormatInt(mm.m.ID, 10)
			}
		}
		addTo(key, mm)
	}

	// Emit threads. Within a thread, members are ordered by UID; threads are
	// ordered by their smallest member id for determinism.
	sort.SliceStable(order, func(i, j int) bool {
		return groups[order[i]].members[0].m.UID < groups[order[j]].members[0].m.UID
	})

	var parts []string
	for _, key := range order {
		g := groups[key]
		sort.SliceStable(g.members, func(i, j int) bool {
			return g.members[i].m.UID < g.members[j].m.UID
		})
		var ids []string
		for _, mm := range g.members {
			ids = append(ids, strconv.FormatUint(uint64(idOf(mm)), 10))
		}
		// RFC 5256: a thread is a parenthesized, space-separated list of message
		// numbers (nesting represents reply structure; a flat chain is acceptable).
		parts = append(parts, "("+strings.Join(ids, " ")+")")
	}
	c.writef("* THREAD %s", strings.Join(parts, ""))
	c.ok(tag, "THREAD completed")
}
