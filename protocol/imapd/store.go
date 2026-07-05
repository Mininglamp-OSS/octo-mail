package imapd

import (
	"io"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdStore handles STORE and UID STORE. args: "<set> <op> (<flags>)" where op is
// FLAGS / +FLAGS / -FLAGS optionally suffixed .SILENT. Applies to the flag set
// and records a ChangeFlags per message (one change-log entry each).
func (c *conn) cmdStore(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	if c.readOnly {
		c.no(tag, "mailbox is read-only")
		return
	}
	setStr, rest := cut(strings.TrimSpace(args), " ")
	rest = strings.TrimSpace(rest)

	// Optional CONDSTORE modifier "(UNCHANGEDSINCE n)" before the op: only
	// messages whose modseq <= n are updated; others are reported as MODIFIED.
	var unchangedSince int64 = -1
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end >= 0 {
			mod := rest[1:end]
			f := strings.Fields(mod)
			if len(f) == 2 && strings.EqualFold(f[0], "UNCHANGEDSINCE") {
				if n, e := strconvParseInt(f[1]); e == nil {
					unchangedSince = n
				}
			}
			rest = strings.TrimSpace(rest[end+1:])
		}
	}

	opTok, flagTok := cut(rest, " ")
	op := strings.ToUpper(opTok)
	silent := strings.HasSuffix(op, ".SILENT")
	op = strings.TrimSuffix(op, ".SILENT")

	flags := parseFlagList(flagTok)
	var modified []uint32 // UIDs rejected by UNCHANGEDSINCE

	// Collect junk-training actions (messageID, ham?) for messages whose \Junk
	// flag changed, to run after the tx commits.
	type trainAction struct {
		m   store.Message
		ham bool
	}
	var trains []trainAction

	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		msgs, err := tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
		if err != nil {
			return err
		}
		var maxUID uint32
		if len(msgs) > 0 {
			maxUID = uint32(msgs[len(msgs)-1].UID)
		}
		var match func(uint32) bool
		if byUID {
			match = parseUIDSet(setStr, maxUID)
		} else {
			match = parseUIDSet(setStr, uint32(len(msgs)))
		}
		for i, m := range msgs {
			seq := uint32(i + 1)
			var sel bool
			if byUID {
				sel = match(uint32(m.UID))
			} else {
				sel = match(seq)
			}
			if !sel {
				continue
			}
			// UNCHANGEDSINCE: skip (report MODIFIED) messages changed since n.
			if unchangedSince >= 0 && int64(m.ModSeq) > unchangedSince {
				modified = append(modified, uint32(m.UID))
				continue
			}
			wasJunk := m.Junk
			applyFlags(&m, op, flags)
			if err := tx.Update(&m); err != nil {
				return err
			}
			// \Junk transition → schedule retrain (spam when gained, ham when lost).
			if c.srv.Junk != nil && m.Junk != wasJunk {
				trains = append(trains, trainAction{m: m, ham: !m.Junk})
			}
			if !silent {
				c.writeFetch(seq, m, fetchReq{flags: true}, byUID)
			}
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	// Retrain the junk filter outside the tx (reads the body from the blob).
	for _, ta := range trains {
		br := c.acc.MessageReader(ta.m)
		data, rerr := io.ReadAll(br)
		br.Close()
		if rerr == nil {
			_ = c.srv.Junk.Train(c.ctx, c.acc.ID(), ta.ham, data)
		}
	}
	if len(modified) > 0 {
		var ids []string
		for _, u := range modified {
			ids = append(ids, strconv.FormatUint(uint64(u), 10))
		}
		c.ok(tag, "[MODIFIED "+strings.Join(ids, ",")+"] STORE completed")
		return
	}
	c.ok(tag, "STORE completed")
}

func parseFlagList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	return strings.Fields(s)
}

// applyFlags mutates m's flags per the STORE op (FLAGS/+FLAGS/-FLAGS).
func applyFlags(m *store.Message, op string, flags []string) {
	set := func(name string, v bool) {
		switch strings.ToLower(name) {
		case `\seen`:
			m.Seen = v
		case `\answered`:
			m.Answered = v
		case `\flagged`:
			m.Flagged = v
		case `\deleted`:
			m.Deleted = v
		case `\draft`:
			m.Draft = v
		case `$junk`, `\junk`:
			m.Junk = v
		case `$notjunk`, `\notjunk`:
			m.Notjunk = v
		default:
			// keyword
			if v {
				if !contains(m.Keywords, name) {
					m.Keywords = append(m.Keywords, name)
				}
			} else {
				m.Keywords = remove(m.Keywords, name)
			}
		}
	}
	switch op {
	case "FLAGS":
		m.Flags = store.Flags{}
		m.Keywords = nil
		for _, f := range flags {
			set(f, true)
		}
	case "+FLAGS":
		for _, f := range flags {
			set(f, true)
		}
	case "-FLAGS":
		for _, f := range flags {
			set(f, false)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func remove(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if !strings.EqualFold(x, s) {
			out = append(out, x)
		}
	}
	return out
}
