package imapd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// cmdESearch implements the extended ESEARCH command with the MULTISEARCH source
// options (RFC 7377): search across one or more mailboxes without selecting them.
//
//	ESEARCH [ IN (scope...) ] [ RETURN (opts) ] criteria
//
// Scope tokens: "selected" (the selected mailbox), "inboxes"/"personal"/
// "subscribed" (all of this account's mailboxes — single-user personal
// namespace), or a quoted/atom mailbox name. Each matching mailbox produces one
// "* ESEARCH (TAG t MAILBOX name UIDVALIDITY v) UID ..." response.
func (c *conn) cmdESearch(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)

	// Optional IN (scope...) source specification.
	var mailboxes []store.Mailbox
	explicitScope := false
	if up := strings.ToUpper(rest); strings.HasPrefix(up, "IN ") {
		explicitScope = true
		after := strings.TrimSpace(rest[len("IN "):])
		if !strings.HasPrefix(after, "(") {
			c.no(tag, "malformed IN scope")
			return
		}
		end := strings.IndexByte(after, ')')
		if end < 0 {
			c.no(tag, "malformed IN scope")
			return
		}
		scopeToks := splitQuotedFields(after[1:end])
		rest = strings.TrimSpace(after[end+1:])

		var all []store.Mailbox
		if err := c.acc.ReadTx(c.ctx, func(tx store.Tx) error {
			var e error
			all, e = tx.QueryMailbox().List()
			return e
		}); err != nil {
			c.no(tag, err.Error())
			return
		}
		seen := map[int64]bool{}
		for _, s := range scopeToks {
			switch strings.ToLower(s) {
			case "selected", "selected-delayed":
				if c.selected != nil && !seen[c.selected.ID] {
					mailboxes = append(mailboxes, *c.selected)
					seen[c.selected.ID] = true
				}
			case "inboxes", "personal", "subscribed":
				for _, mb := range all {
					if strings.EqualFold(s, "subscribed") && !mb.Subscribed {
						continue
					}
					if !seen[mb.ID] {
						mailboxes = append(mailboxes, mb)
						seen[mb.ID] = true
					}
				}
			default:
				name := normalizeMailbox(s)
				for _, mb := range all {
					if mb.Name == name && !seen[mb.ID] {
						mailboxes = append(mailboxes, mb)
						seen[mb.ID] = true
					}
				}
			}
		}
	} else if c.selected != nil {
		mailboxes = []store.Mailbox{*c.selected}
	}

	if !explicitScope && c.selected == nil {
		c.no(tag, "no mailbox selected and no IN scope given")
		return
	}

	// Optional RETURN (opts).
	retOpts := []string{}
	if up := strings.ToUpper(rest); strings.HasPrefix(up, "RETURN ") {
		after := strings.TrimSpace(rest[len("RETURN "):])
		if !strings.HasPrefix(after, "(") {
			c.no(tag, "malformed RETURN clause")
			return
		}
		end := strings.IndexByte(after, ')')
		if end < 0 {
			c.no(tag, "malformed RETURN clause")
			return
		}
		retOpts = strings.Fields(strings.ToUpper(after[1:end]))
		rest = strings.TrimSpace(after[end+1:])
	}
	crit := strings.TrimSpace(rest)

	wantMin, wantMax, wantAll, wantCount := parseESearchReturnOpts(retOpts)

	for _, mb := range mailboxes {
		mb := mb
		msgs, ok := c.searchMatchesIn(tag, &mb, crit)
		if !ok {
			return // error already reported
		}
		var ids []string
		for _, mm := range msgs {
			ids = append(ids, strconv.FormatUint(uint64(mm.m.UID), 10))
		}
		// Always include the MAILBOX/UIDVALIDITY correlators for a multi-mailbox
		// search so the client can attribute results (RFC 7377 §2.1).
		parts := []string{fmt.Sprintf("(TAG %s MAILBOX %s UIDVALIDITY %d)", quote(tag), quote(mb.Name), mb.UIDValidity), "UID"}
		if wantMin && len(ids) > 0 {
			parts = append(parts, "MIN "+ids[0])
		}
		if wantMax && len(ids) > 0 {
			parts = append(parts, "MAX "+ids[len(ids)-1])
		}
		if wantCount {
			parts = append(parts, fmt.Sprintf("COUNT %d", len(ids)))
		}
		if wantAll && len(ids) > 0 {
			parts = append(parts, "ALL "+compressUIDList(ids))
		}
		// Suppress an all-empty ESEARCH line (no data items and no matches) unless
		// COUNT was requested (COUNT 0 is meaningful).
		if len(ids) == 0 && !wantCount {
			continue
		}
		c.writef("* ESEARCH %s", strings.Join(parts, " "))
	}
	c.ok(tag, "ESEARCH completed")
}

// parseESearchReturnOpts interprets ESEARCH RETURN options; with none given, ALL
// is implied (RFC 4731 §3.1).
func parseESearchReturnOpts(opts []string) (min, max, all, count bool) {
	for _, o := range opts {
		switch o {
		case "MIN":
			min = true
		case "MAX":
			max = true
		case "ALL":
			all = true
		case "COUNT":
			count = true
		}
	}
	if !min && !max && !all && !count {
		all = true
	}
	return
}
