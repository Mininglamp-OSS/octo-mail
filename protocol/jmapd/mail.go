package jmapd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	moxmessage "github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

// emailID encodes a message's JMAP Email id: "E<effectiveEmailID>". One Email
// may span several mailboxes (sibling rows sharing an email_id); the id is that
// shared identity, so the same message in two folders is ONE Email — the JMAP
// multi-mailbox model. Opaque to clients.
func emailID(m store.Message) string {
	return "E" + strconv.FormatInt(m.EffectiveEmailID(), 10)
}

// parseEmailGroupID decodes an "E<n>" JMAP Email id to its effective email id.
func parseEmailGroupID(id string) (int64, bool) {
	if len(id) < 2 || id[0] != 'E' {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil
}

// emailGroup loads all live rows of an Email (across mailboxes) by its JMAP id.
func (s *Server) emailGroup(tx store.Tx, acc store.Account, jmapID string) ([]store.Message, bool) {
	gid, ok := parseEmailGroupID(jmapID)
	if !ok {
		return nil, false
	}
	msgs, err := acc.MessagesByEmailID(tx, gid)
	if err != nil || len(msgs) == 0 {
		return nil, false
	}
	return msgs, true
}

// mailboxIDsOf returns the JMAP mailboxIds set for an email group: {mailboxID: true}.
func mailboxIDsOf(msgs []store.Message) map[string]bool {
	set := map[string]bool{}
	for _, m := range msgs {
		set[strconv.FormatInt(m.MailboxID, 10)] = true
	}
	return set
}

// mergedKeywords returns the union of JMAP keywords across an email group's rows.
func mergedKeywords(msgs []store.Message) map[string]bool {
	kw := map[string]bool{}
	for _, m := range msgs {
		for k, v := range jmapKeywords(m) {
			if v {
				kw[k] = true
			}
		}
	}
	return kw
}

func mailboxState(ctx context.Context, acc store.Account) string {
	st, _ := accountState(ctx, acc)
	return st
}

// Mailbox/get: list the account's mailboxes as JMAP Mailbox objects.
func (s *Server) mailboxGet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var list []map[string]any
	err := acc.Tx(ctx, func(tx store.Tx) error {
		mbs, e := tx.QueryMailbox().List()
		if e != nil {
			return e
		}
		for _, mb := range mbs {
			role := jmapRole(mb)
			list = append(list, map[string]any{
				"id":           strconv.FormatInt(mb.ID, 10),
				"name":         mb.Name,
				"role":         role,
				"totalEmails":  mb.Total,
				"unreadEmails": mb.Unread,
				"sortOrder":    0,
			})
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	return "Mailbox/get", map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"state":     mailboxState(ctx, acc),
		"list":      list,
		"notFound":  []string{},
	}
}

func jmapRole(mb store.Mailbox) any {
	switch {
	case strings.EqualFold(mb.Name, "Inbox"):
		return "inbox"
	case mb.Sent:
		return "sent"
	case mb.Draft:
		return "drafts"
	case mb.Trash:
		return "trash"
	case mb.Junk:
		return "junk"
	case mb.Archive:
		return "archive"
	default:
		return nil
	}
}

// Email/query: return message ids matching a filter, sorted, with position/limit
// (RFC 8621 §4.4). filter supports inMailbox, from/to/subject/text substring,
// before/after (receivedAt), minSize/maxSize, hasKeyword/notKeyword. sort
// supports receivedAt and size, ascending or descending. Full-text (text/body)
// uses the async fts projection.
func (s *Server) emailQuery(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	filt := parseEmailFilter(inv.args["filter"])
	sortProp, sortAsc := parseEmailSort(inv.args["sort"])
	position := int(jsonNum(inv.args["position"]))
	limit := int(jsonNum(inv.args["limit"]))

	// Precompute fts hits for a text/body term if present. Keyed by message ID
	// (globally unique) — NOT UID, which is only unique per mailbox and would
	// collide across mailboxes when no inMailbox filter is set.
	var ftsHits map[int64]bool
	if filt.text != "" {
		ftsHits = map[int64]bool{}
		_ = acc.Tx(ctx, func(tx store.Tx) error {
			q := tx.QueryMessage()
			if filt.mailboxID != 0 {
				q = q.FilterMailbox(filt.mailboxID)
			}
			ms, e := q.FilterFTS(filt.text).List()
			if e != nil {
				return e
			}
			for _, mm := range ms {
				ftsHits[mm.ID] = true
			}
			return nil
		})
	}

	type row struct {
		id  string
		rcv int64
		sz  int64
	}
	var rows []row
	err := acc.Tx(ctx, func(tx store.Tx) error {
		q := tx.QueryMessage()
		if filt.mailboxID != 0 {
			q = q.FilterMailbox(filt.mailboxID)
		}
		msgs, e := q.SortUID().List()
		if e != nil {
			return e
		}
		// Dedup by email group: one row may match per mailbox, but an Email is a
		// single object. Keep the first matching row per effective email id.
		seen := map[int64]bool{}
		for _, m := range msgs {
			if !s.emailMatchesFilter(acc, m, filt, ftsHits) {
				continue
			}
			gid := m.EffectiveEmailID()
			if seen[gid] {
				continue
			}
			seen[gid] = true
			rows = append(rows, row{id: emailID(m), rcv: m.Received.UnixNano(), sz: m.Size})
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}

	// Sort.
	sort.SliceStable(rows, func(i, j int) bool {
		var less bool
		switch sortProp {
		case "size":
			less = rows[i].sz < rows[j].sz
		default: // receivedAt
			less = rows[i].rcv < rows[j].rcv
		}
		if !sortAsc {
			return !less
		}
		return less
	})

	total := len(rows)
	if position < 0 {
		position = 0
	}
	if position > len(rows) {
		position = len(rows)
	}
	rows = rows[position:]
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.id)
	}

	st, _ := accountState(ctx, acc)
	return "Email/query", map[string]any{
		"accountId":  strconv.FormatInt(acc.ID(), 10),
		"queryState": st,
		"ids":        ids,
		"total":      total,
		"position":   position,
	}
}

// emailFilter is a parsed Email/query filter.
type emailFilter struct {
	mailboxID              int64
	from, to, subject      string
	text                   string
	before, after          string // receivedAt bounds (RFC3339 date/time prefix compare)
	minSize, maxSize       int64
	hasKeyword, notKeyword string
}

func parseEmailFilter(raw json.RawMessage) emailFilter {
	var f emailFilter
	if raw == nil {
		return f
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return f
	}
	str := func(k string) string {
		var s string
		if v, ok := m[k]; ok {
			_ = json.Unmarshal(v, &s)
		}
		return s
	}
	f.mailboxID = jsonInt64(raw, "inMailbox")
	f.from = str("from")
	f.to = str("to")
	f.subject = str("subject")
	f.text = str("text")
	if f.text == "" {
		f.text = str("body")
	}
	f.before = str("before")
	f.after = str("after")
	f.hasKeyword = str("hasKeyword")
	f.notKeyword = str("notKeyword")
	if v, ok := m["minSize"]; ok {
		_ = json.Unmarshal(v, &f.minSize)
	}
	if v, ok := m["maxSize"]; ok {
		_ = json.Unmarshal(v, &f.maxSize)
	}
	return f
}

func parseEmailSort(raw json.RawMessage) (prop string, asc bool) {
	prop, asc = "receivedAt", true
	if raw == nil {
		return
	}
	var arr []map[string]json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
		return
	}
	first := arr[0]
	if v, ok := first["property"]; ok {
		_ = json.Unmarshal(v, &prop)
	}
	if v, ok := first["isAscending"]; ok {
		_ = json.Unmarshal(v, &asc)
	}
	return
}

// emailMatchesFilter evaluates the non-mailbox filter predicates for a message.
func (s *Server) emailMatchesFilter(acc store.Account, m store.Message, f emailFilter, ftsHits map[int64]bool) bool {
	if f.minSize > 0 && m.Size < f.minSize {
		return false
	}
	if f.maxSize > 0 && m.Size > f.maxSize {
		return false
	}
	if f.after != "" && !m.Received.IsZero() && m.Received.UTC().Format("2006-01-02T15:04:05Z") < f.after {
		return false
	}
	if f.before != "" && !m.Received.IsZero() && m.Received.UTC().Format("2006-01-02T15:04:05Z") >= f.before {
		return false
	}
	if f.hasKeyword != "" && !hasKeyword(m, f.hasKeyword) {
		return false
	}
	if f.notKeyword != "" && hasKeyword(m, f.notKeyword) {
		return false
	}
	if f.text != "" && (ftsHits == nil || !ftsHits[m.ID]) {
		return false
	}
	// Header substring filters need the parsed message.
	if f.from != "" || f.to != "" || f.subject != "" {
		br := acc.MessageReader(m)
		data, _ := io.ReadAll(br)
		br.Close()
		part, _ := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
		env := part.Envelope
		if env == nil {
			return false
		}
		if f.subject != "" && !strings.Contains(strings.ToLower(env.Subject), strings.ToLower(f.subject)) {
			return false
		}
		if f.from != "" && !addrsContain(env.From, f.from) {
			return false
		}
		if f.to != "" && !addrsContain(env.To, f.to) {
			return false
		}
	}
	return true
}

func addrsContain(as []moxmessage.Address, sub string) bool {
	sub = strings.ToLower(sub)
	for _, a := range as {
		if strings.Contains(strings.ToLower(a.Name+" "+a.User+"@"+a.Host), sub) {
			return true
		}
	}
	return false
}

// hasKeyword reports whether a message has the given JMAP keyword ($seen etc).
func hasKeyword(m store.Message, kw string) bool {
	switch strings.ToLower(kw) {
	case "$seen":
		return m.Seen
	case "$flagged":
		return m.Flagged
	case "$answered":
		return m.Answered
	case "$draft":
		return m.Draft
	case "$junk":
		return m.Junk
	}
	for _, k := range m.Keywords {
		if strings.EqualFold(k, kw) {
			return true
		}
	}
	return false
}

func jsonNum(raw json.RawMessage) int64 {
	if raw == nil {
		return 0
	}
	var n int64
	_ = json.Unmarshal(raw, &n)
	return n
}

// Email/get: return Email objects for the requested ids (subset of properties).
func (s *Server) emailGet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var ids []string
	_ = json.Unmarshal(inv.args["ids"], &ids)

	var list []map[string]any
	var notFound []string
	err := acc.Tx(ctx, func(tx store.Tx) error {
		for _, id := range ids {
			group, ok := s.emailGroup(tx, acc, id)
			if !ok {
				notFound = append(notFound, id)
				continue
			}
			// The representative row (lowest mailbox_id) carries content; the group
			// gives the multi-mailbox membership and merged keywords.
			m := group[0]
			obj := map[string]any{
				"id":         id,
				"mailboxIds": mailboxIDsOf(group),
				"size":       m.Size,
				"keywords":   mergedKeywords(group),
			}
			// threadId from the async threading projection (0 until folded).
			if m.ThreadID != 0 {
				obj["threadId"] = "T" + strconv.FormatInt(m.ThreadID, 10)
			}
			if !m.Received.IsZero() {
				obj["receivedAt"] = m.Received.UTC().Format("2006-01-02T15:04:05Z")
			}
			// Parse the message for rich properties: envelope headers + body.
			br := acc.MessageReader(m)
			data, _ := io.ReadAll(br)
			br.Close()
			obj["preview"] = preview(data)
			addEmailContent(obj, data)
			list = append(list, obj)
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	st, _ := accountState(ctx, acc)
	return "Email/get", map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"state":     st,
		"list":      list,
		"notFound":  emptyIfNil(notFound),
	}
}

// Email/changes: THE symmetry with IMAP CONDSTORE. Given sinceState=n, return
// ids created/updated/destroyed with modseq > n — the same changelog replay.
func (s *Server) emailChanges(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var sinceState string
	_ = json.Unmarshal(inv.args["sinceState"], &sinceState)
	since, _ := strconv.ParseInt(sinceState, 10, 64)

	var created, updated []string
	err := acc.Tx(ctx, func(tx store.Tx) error {
		// Messages whose changelog offset (modseq) is greater than sinceState.
		msgs, e := tx.QueryMessage().FilterModSeqGreater(store.ModSeq(since)).SortUID().List()
		if e != nil {
			return e
		}
		// Collapse rows to their email group. An email is "created" only if its
		// original row (the one whose id is the group id) was created since; a
		// changed sibling (new mailbox membership) counts as an update.
		createdSet := map[int64]bool{}
		updatedSet := map[int64]bool{}
		for _, m := range msgs {
			gid := m.EffectiveEmailID()
			if m.EmailID == 0 && int64(m.CreateSeq) > since {
				createdSet[gid] = true
			} else {
				updatedSet[gid] = true
			}
		}
		for gid := range createdSet {
			created = append(created, "E"+strconv.FormatInt(gid, 10))
			delete(updatedSet, gid) // created wins over updated
		}
		for gid := range updatedSet {
			updated = append(updated, "E"+strconv.FormatInt(gid, 10))
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	newState, _ := accountState(ctx, acc)
	return "Email/changes", map[string]any{
		"accountId":      strconv.FormatInt(acc.ID(), 10),
		"oldState":       sinceState,
		"newState":       newState,
		"hasMoreChanges": false,
		"created":        emptyIfNil(created),
		"updated":        emptyIfNil(updated),
		"destroyed":      []string{},
	}
}

// Email/set: create (draft from an uploaded blob), update (keywords), and
// destroy (expunge). create references a blobId from the upload endpoint plus
// mailboxIds and keywords; the message is delivered into the chosen mailbox.
func (s *Server) emailSet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var create map[string]map[string]json.RawMessage
	var update map[string]map[string]json.RawMessage
	var destroy []string
	_ = json.Unmarshal(inv.args["create"], &create)
	_ = json.Unmarshal(inv.args["update"], &update)
	_ = json.Unmarshal(inv.args["destroy"], &destroy)

	created := map[string]any{}
	notCreated := map[string]any{}
	updated := map[string]any{}
	notUpdated := map[string]any{}
	destroyed := []string{}
	notDestroyed := map[string]any{}

	// create: deliver an uploaded blob as a message. Done outside the keyword tx
	// because DeliverMailbox opens its own transaction.
	for cid, obj := range create {
		res, ok := s.emailCreate(ctx, acc, obj)
		if !ok {
			notCreated[cid] = map[string]any{"type": "invalidProperties"}
			continue
		}
		created[cid] = res
	}

	err := acc.Tx(ctx, func(tx store.Tx) error {
		for id, patch := range update {
			group, ok := s.emailGroup(tx, acc, id)
			if !ok {
				notUpdated[id] = map[string]any{"type": "notFound"}
				continue
			}
			if e := s.emailUpdate(ctx, tx, acc, group, patch); e != nil {
				if e == errNotFoundJMAP {
					notUpdated[id] = map[string]any{"type": "notFound"}
					continue
				}
				return e
			}
			updated[id] = nil
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}

	// destroy: expunge every row of the email group (all its mailbox memberships).
	for _, id := range destroy {
		derr := acc.Tx(ctx, func(tx store.Tx) error {
			group, ok := s.emailGroup(tx, acc, id)
			if !ok {
				notDestroyed[id] = map[string]any{"type": "notFound"}
				return nil
			}
			for _, m := range group {
				mb, e := findMailboxByID(tx, acc, m.MailboxID)
				if e != nil || mb == nil {
					continue
				}
				if _, _, e := acc.MessageRemove(tx, 0, mb, store.RemoveOpts{Expunge: true}, m); e != nil {
					return e
				}
			}
			destroyed = append(destroyed, id)
			return nil
		})
		if derr != nil {
			notDestroyed[id] = map[string]any{"type": "serverFail"}
		}
	}

	newState, _ := accountState(ctx, acc)
	return "Email/set", map[string]any{
		"accountId":    strconv.FormatInt(acc.ID(), 10),
		"oldState":     "",
		"newState":     newState,
		"created":      created,
		"notCreated":   notCreated,
		"updated":      updated,
		"notUpdated":   notUpdated,
		"destroyed":    destroyed,
		"notDestroyed": notDestroyed,
	}
}

// emailUpdate applies a JMAP Email/set update patch to an email group: keyword
// changes fan out to every row (so \Seen etc. is consistent across folders), and
// mailboxIds set changes reconcile membership — new mailboxIds materialize a
// sibling row (AddSibling), removed ones expunge that mailbox's row. Both the
// full-value form ("keywords", "mailboxIds") and JMAP patch form ("keywords/x",
// "mailboxIds/id") are supported.
func (s *Server) emailUpdate(ctx context.Context, tx store.Tx, acc store.Account, group []store.Message, patch map[string]json.RawMessage) error {
	// --- keyword changes: fan out to all rows in the group. ---
	hasKeywordChange := false
	for k := range patch {
		if k == "keywords" || strings.HasPrefix(k, "keywords/") {
			hasKeywordChange = true
			break
		}
	}
	if hasKeywordChange {
		for i := range group {
			m := group[i]
			if raw, ok := patch["keywords"]; ok {
				// Full replacement: clear then set from the map.
				var kw map[string]bool
				_ = json.Unmarshal(raw, &kw)
				m.Flags = store.Flags{}
				m.Keywords = nil
				applyJMAPKeywords(&m, kw)
			}
			applyKeywordPatch(&m, patch) // keywords/x patch entries
			if e := tx.Update(&m); e != nil {
				return e
			}
		}
	}

	// --- mailboxIds changes: reconcile the membership set. ---
	want, hasSet := desiredMailboxIDs(patch, group)
	if !hasSet {
		return nil
	}
	current := map[int64]store.Message{}
	for _, m := range group {
		current[m.MailboxID] = m
	}
	// Add rows for wanted mailboxes not currently present.
	rep := group[0]
	for mbID := range want {
		if _, ok := current[mbID]; ok {
			continue
		}
		mb, e := findMailboxByID(tx, acc, mbID)
		if e != nil || mb == nil {
			return errNotFoundJMAP
		}
		if _, _, e := acc.AddSibling(tx, rep, mb); e != nil {
			return e
		}
	}
	// Expunge rows for mailboxes no longer wanted.
	for mbID, m := range current {
		if want[mbID] {
			continue
		}
		mb, e := findMailboxByID(tx, acc, mbID)
		if e != nil || mb == nil {
			continue
		}
		if _, _, e := acc.MessageRemove(tx, 0, mb, store.RemoveOpts{Expunge: true}, m); e != nil {
			return e
		}
	}
	return nil
}

// desiredMailboxIDs computes the target mailbox-id set from an Email/set update
// patch, starting from the group's current membership. Returns hasSet=false when
// the patch touches no mailboxIds. Supports "mailboxIds" (full map) and
// "mailboxIds/<id>" (per-key true/false) forms.
func desiredMailboxIDs(patch map[string]json.RawMessage, group []store.Message) (map[int64]bool, bool) {
	want := map[int64]bool{}
	for _, m := range group {
		want[m.MailboxID] = true
	}
	touched := false
	if raw, ok := patch["mailboxIds"]; ok {
		touched = true
		want = map[int64]bool{}
		var set map[string]bool
		if json.Unmarshal(raw, &set) == nil {
			for id, v := range set {
				if !v {
					continue
				}
				if n, e := strconv.ParseInt(id, 10, 64); e == nil {
					want[n] = true
				}
			}
		}
	}
	for k, raw := range patch {
		if !strings.HasPrefix(k, "mailboxIds/") {
			continue
		}
		touched = true
		idStr := strings.TrimPrefix(k, "mailboxIds/")
		n, e := strconv.ParseInt(idStr, 10, 64)
		if e != nil {
			continue
		}
		var v bool
		_ = json.Unmarshal(raw, &v)
		if v {
			want[n] = true
		} else {
			delete(want, n)
		}
	}
	return want, touched
}

// emailCreate delivers an uploaded blob as a message (JMAP draft creation). The
// create object references blobId (from upload), mailboxIds (target), and
// keywords. Returns the created Email's id + size.
func (s *Server) emailCreate(ctx context.Context, acc store.Account, obj map[string]json.RawMessage) (map[string]any, bool) {
	if s.Blob == nil {
		return nil, false
	}
	var blobID string
	_ = json.Unmarshal(obj["blobId"], &blobID)
	blobTenant, ref, ok := parseUploadBlobID(blobID)
	if !ok {
		return nil, false
	}
	// Isolation: the blobId is client-controlled. (1) Its tenant component must
	// equal the authenticated account's tenant — a blob is only ever read under
	// the auth tenant, never the id's. (2) Its ref must be a canonical sha256
	// content-address, so a crafted ref (e.g. containing "../") can't traverse
	// out of the tenant key prefix. Both are also enforced in the blob store.
	tenantID := acc.TenantID()
	if blobTenant != tenantID || !blob.Ref(ref).Valid() {
		return nil, false
	}
	// Resolve target mailbox: first key of mailboxIds, else "Drafts".
	mailbox := "Drafts"
	var mids map[string]bool
	if json.Unmarshal(obj["mailboxIds"], &mids) == nil {
		for id := range mids {
			if n, e := strconv.ParseInt(id, 10, 64); e == nil {
				if name, ok := s.mailboxNameByID(ctx, acc, n); ok {
					mailbox = name
				}
			}
		}
	}
	// Read the uploaded bytes.
	rd, err := s.Blob.Open(ctx, tenantID, blob.Ref(ref))
	if err != nil {
		return nil, false
	}
	data, _ := io.ReadAll(rd)
	rd.Close()

	m := &store.Message{}
	// Apply keywords from the create object.
	var kw map[string]bool
	if json.Unmarshal(obj["keywords"], &kw) == nil {
		applyJMAPKeywords(m, kw)
	}
	if _, err := acc.DeliverMailbox(mailbox, m, memBlob(data)); err != nil {
		return nil, false
	}
	return map[string]any{
		"id":   emailID(*m),
		"size": m.Size,
	}, true
}

// mailboxNameByID resolves a mailbox id to its name.
func (s *Server) mailboxNameByID(ctx context.Context, acc store.Account, id int64) (string, bool) {
	var name string
	found := false
	_ = acc.Tx(ctx, func(tx store.Tx) error {
		mb, e := findMailboxByID(tx, acc, id)
		if e == nil && mb != nil {
			name = mb.Name
			found = true
		}
		return nil
	})
	return name, found
}

// parseUploadBlobID decodes "U<tenantID>-<hash>".
func parseUploadBlobID(id string) (tenantID int64, ref string, ok bool) {
	if !strings.HasPrefix(id, "U") {
		return 0, "", false
	}
	rest := id[1:]
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return 0, "", false
	}
	t, err := strconv.ParseInt(rest[:dash], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return t, rest[dash+1:], true
}

// applyJMAPKeywords sets message flags from a JMAP keywords map, routing system
// keywords through the canonical store.Flags parser and treating the rest as
// free-form keywords.
func applyJMAPKeywords(m *store.Message, kw map[string]bool) {
	for k, v := range kw {
		if m.Flags.SetByName(k, v) {
			continue
		}
		if v {
			m.Keywords = append(m.Keywords, k)
		}
	}
}

// memBlob adapts bytes to store.BlobReader.
func memBlob(b []byte) store.BlobReader { return &memBlobReader{data: b} }

type memBlobReader struct {
	data []byte
	off  int64
}

func (m *memBlobReader) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *memBlobReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memBlobReader) Size() int64  { return int64(len(m.data)) }
func (m *memBlobReader) Close() error { return nil }

// Thread/get: return the emailIds belonging to each requested threadId. Thread
// ids are "T<id>"; membership is read from the async threading projection
// (messages.thread_id). Emails are returned in delivery order.
func (s *Server) threadGet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var ids []string
	_ = json.Unmarshal(inv.args["ids"], &ids)

	var list []map[string]any
	var notFound []string
	err := acc.Tx(ctx, func(tx store.Tx) error {
		// Load all messages once; group by threadId.
		msgs, e := tx.QueryMessage().SortUID().List()
		if e != nil {
			return e
		}
		byThread := map[int64][]string{}
		seen := map[int64]map[int64]bool{} // threadID -> set of effective email ids
		for _, m := range msgs {
			tid := m.ThreadID
			gid := m.EffectiveEmailID()
			if seen[tid] == nil {
				seen[tid] = map[int64]bool{}
			}
			if seen[tid][gid] {
				continue // sibling in another mailbox: same Email, list once
			}
			seen[tid][gid] = true
			byThread[tid] = append(byThread[tid], emailID(m))
		}
		for _, id := range ids {
			tid, ok := parseThreadID(id)
			if !ok {
				notFound = append(notFound, id)
				continue
			}
			emails, present := byThread[tid]
			if !present {
				notFound = append(notFound, id)
				continue
			}
			list = append(list, map[string]any{"id": id, "emailIds": emails})
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	st, _ := accountState(ctx, acc)
	return "Thread/get", map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"state":     st,
		"list":      emptyList(list),
		"notFound":  emptyIfNil(notFound),
	}
}

// Mailbox/set: create and destroy mailboxes (RFC 8621 §2.5). create maps a
// client-side id to {name}; destroy is a list of mailbox ids.
func (s *Server) mailboxSet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var create map[string]map[string]json.RawMessage
	var destroy []string
	_ = json.Unmarshal(inv.args["create"], &create)
	_ = json.Unmarshal(inv.args["destroy"], &destroy)

	created := map[string]any{}
	notCreated := map[string]any{}
	destroyed := []string{}
	notDestroyed := map[string]any{}

	err := acc.Tx(ctx, func(tx store.Tx) error {
		for cid, obj := range create {
			var name string
			_ = json.Unmarshal(obj["name"], &name)
			if name == "" {
				notCreated[cid] = map[string]any{"type": "invalidProperties", "properties": []string{"name"}}
				continue
			}
			mb, _, _, exists, e := acc.MailboxCreate(tx, name, store.SpecialUse{})
			if e != nil {
				return e
			}
			if exists {
				notCreated[cid] = map[string]any{"type": "alreadyExists"}
				continue
			}
			created[cid] = map[string]any{"id": strconv.FormatInt(mb.ID, 10), "totalEmails": 0, "unreadEmails": 0}
		}
		for _, id := range destroy {
			mbID, e := strconv.ParseInt(id, 10, 64)
			if e != nil {
				notDestroyed[id] = map[string]any{"type": "notFound"}
				continue
			}
			mb, e := findMailboxByID(tx, acc, mbID)
			if e != nil || mb == nil {
				notDestroyed[id] = map[string]any{"type": "notFound"}
				continue
			}
			_, hasChildren, e := acc.MailboxDelete(ctx, tx, mb)
			if e != nil {
				return e
			}
			if hasChildren {
				notDestroyed[id] = map[string]any{"type": "mailboxHasChild"}
				continue
			}
			destroyed = append(destroyed, id)
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	newState, _ := accountState(ctx, acc)
	return "Mailbox/set", map[string]any{
		"accountId":    strconv.FormatInt(acc.ID(), 10),
		"oldState":     "",
		"newState":     newState,
		"created":      created,
		"notCreated":   notCreated,
		"destroyed":    destroyed,
		"notDestroyed": notDestroyed,
	}
}

// findMailboxByID locates a mailbox by id via the mailbox query.
func findMailboxByID(tx store.Tx, acc store.Account, id int64) (*store.Mailbox, error) {
	mbs, err := tx.QueryMailbox().List()
	if err != nil {
		return nil, err
	}
	for i := range mbs {
		if mbs[i].ID == id {
			return &mbs[i], nil
		}
	}
	return nil, nil
}

func parseThreadID(id string) (int64, bool) {
	if !strings.HasPrefix(id, "T") {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil
}

func emptyList(l []map[string]any) []map[string]any {
	if l == nil {
		return []map[string]any{}
	}
	return l
}

// --- helpers ---

// jmapKeywords maps flags/keywords to JMAP keyword map ($seen, $flagged, ...)
// via the canonical registry in store.Flags, so it cannot drift from the IMAP
// and WebAPI renderers.
func jmapKeywords(m store.Message) map[string]bool {
	return m.Flags.JMAPKeywords(m.Keywords)
}

// applyKeywordPatch applies a JMAP patch like {"keywords/$seen": true}.
func applyKeywordPatch(m *store.Message, patch map[string]json.RawMessage) {
	for k, raw := range patch {
		if !strings.HasPrefix(k, "keywords/") {
			continue
		}
		name := strings.TrimPrefix(k, "keywords/")
		var v bool
		_ = json.Unmarshal(raw, &v)
		switch strings.ToLower(name) {
		case "$seen":
			m.Seen = v
		case "$answered":
			m.Answered = v
		case "$flagged":
			m.Flagged = v
		case "$draft":
			m.Draft = v
		default:
			if v {
				if !containsFold(m.Keywords, name) {
					m.Keywords = append(m.Keywords, name)
				}
			} else {
				m.Keywords = removeFold(m.Keywords, name)
			}
		}
	}
}

func containsFold(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
func removeFold(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if !strings.EqualFold(x, s) {
			out = append(out, x)
		}
	}
	return out
}

// addEmailContent parses the raw message and adds JMAP rich properties: header
// fields (subject/from/to/cc/messageId), bodyStructure, bodyValues (text body),
// and hasAttachment. Reuses the message parser; missing fields are omitted.
func addEmailContent(obj map[string]any, data []byte) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if env := part.Envelope; env != nil {
		obj["subject"] = env.Subject
		obj["from"] = jmapAddrs(env.From)
		obj["to"] = jmapAddrs(env.To)
		if len(env.CC) > 0 {
			obj["cc"] = jmapAddrs(env.CC)
		}
		if env.MessageID != "" {
			obj["messageId"] = []string{env.MessageID}
		}
		if env.InReplyTo != "" {
			obj["inReplyTo"] = []string{env.InReplyTo}
		}
	}
	if err != nil && part.Envelope == nil {
		return
	}
	// bodyStructure: minimal EmailBodyPart tree.
	obj["bodyStructure"] = jmapBodyPart(&part, "1")
	// bodyValues: the text of the first text/* part, keyed by its partId.
	bv := map[string]any{}
	collectBodyValues(&part, "1", data, bv)
	obj["bodyValues"] = bv
	obj["hasAttachment"] = messageHasAttachment(&part)
}

// jmapAddrs converts envelope addresses to JMAP EmailAddress objects.
func jmapAddrs(as []moxmessage.Address) []map[string]any {
	var out []map[string]any
	for _, a := range as {
		email := a.User + "@" + a.Host
		out = append(out, map[string]any{"name": a.Name, "email": email})
	}
	if out == nil {
		return []map[string]any{}
	}
	return out
}

// jmapBodyPart renders a JMAP EmailBodyPart for a MIME part.
func jmapBodyPart(p *moxmessage.Part, partID string) map[string]any {
	mt := p.MediaType
	if mt == "" {
		mt = "TEXT"
	}
	st := p.MediaSubType
	if st == "" {
		st = "PLAIN"
	}
	obj := map[string]any{
		"type": strings.ToLower(mt + "/" + st),
		"size": p.DecodedSize,
	}
	if len(p.Parts) > 0 {
		var subs []map[string]any
		for i := range p.Parts {
			subs = append(subs, jmapBodyPart(&p.Parts[i], partID+"."+strconv.Itoa(i+1)))
		}
		obj["subParts"] = subs
	} else {
		obj["partId"] = partID
	}
	return obj
}

// collectBodyValues fills bv[partId] = {value: <text>} for text/* leaf parts.
func collectBodyValues(p *moxmessage.Part, partID string, full []byte, bv map[string]any) {
	if len(p.Parts) > 0 {
		for i := range p.Parts {
			collectBodyValues(&p.Parts[i], partID+"."+strconv.Itoa(i+1), full, bv)
		}
		return
	}
	if !strings.EqualFold(p.MediaType, "TEXT") && p.MediaType != "" {
		return
	}
	// Read this part's decoded body via its reader.
	r := p.Reader()
	if r == nil {
		return
	}
	b, _ := io.ReadAll(r)
	bv[partID] = map[string]any{"value": string(b), "isTruncated": false}
}

// messageHasAttachment reports whether any part is a non-inline attachment.
func messageHasAttachment(p *moxmessage.Part) bool {
	for i := range p.Parts {
		sub := &p.Parts[i]
		if !strings.EqualFold(sub.MediaType, "TEXT") && !strings.EqualFold(sub.MediaType, "MULTIPART") && sub.MediaType != "" {
			return true
		}
		if messageHasAttachment(sub) {
			return true
		}
	}
	return false
}

// preview returns a short plain-text snippet for the list view. It parses the
// MIME tree and takes the first text/plain leaf (falling back to a de-tagged
// text/html leaf), so multipart and HTML messages get a clean snippet instead of
// raw MIME boundaries. Capped at 140 chars.
func preview(data []byte) string {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	s := ""
	if err == nil || part.Envelope != nil {
		s = previewFromPart(&part)
	}
	if s == "" {
		// Fallback: raw text after the first blank line (non-MIME messages).
		s = string(data)
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			s = s[i+4:]
		}
	}
	s = strings.Join(strings.Fields(s), " ") // collapse whitespace/newlines
	if len(s) > 140 {
		s = s[:140]
	}
	return s
}

// previewFromPart extracts snippet text: prefer the first text/plain leaf, else
// the first text/html leaf with tags stripped.
func previewFromPart(p *moxmessage.Part) string {
	var plain, html string
	var walk func(n *moxmessage.Part)
	walk = func(n *moxmessage.Part) {
		if len(n.Parts) > 0 {
			for i := range n.Parts {
				walk(&n.Parts[i])
			}
			return
		}
		if !strings.EqualFold(n.MediaType, "TEXT") {
			return
		}
		r := n.Reader()
		if r == nil {
			return
		}
		b, _ := io.ReadAll(r)
		if strings.EqualFold(n.MediaSubType, "HTML") {
			if html == "" {
				html = stripTags(string(b))
			}
		} else if plain == "" {
			plain = string(b)
		}
	}
	walk(p)
	if plain != "" {
		return plain
	}
	return html
}

// stripTags removes HTML tags for a text-only preview (not for rendering).
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func jsonInt64(raw json.RawMessage, key string) int64 {
	if raw == nil {
		return 0
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	// Accept both number and string forms.
	var n int64
	if json.Unmarshal(v, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(v, &str) == nil {
		n, _ = strconv.ParseInt(str, 10, 64)
	}
	return n
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// emailSubmissionSet implements EmailSubmission/set (RFC 8621 §7): the JMAP send
// path. Each create references an existing emailId and an envelope (mailFrom +
// rcptTo); we read that message's body from the blob store and enqueue it to the
// shared outbound queue via the Submitter — the exact same queue the SMTP
// submission path (port 587) feeds. This is the JMAP counterpart proving send is
// protocol-agnostic: one queue, two front doors.
func (s *Server) emailSubmissionSet(ctx context.Context, acc store.Account, scope directory.TenantScope, login string, inv invocation) (string, any) {
	if s.Submission == nil {
		return "error", map[string]any{"type": "serverFail", "description": "submission not enabled"}
	}
	var create map[string]map[string]json.RawMessage
	_ = json.Unmarshal(inv.args["create"], &create)

	created := map[string]any{}
	notCreated := map[string]any{}

	// The only valid identity for this account is the login's own address.
	validIdentity := "I" + strconv.FormatInt(acc.ID(), 10)

	for cid, obj := range create {
		var emailID string
		_ = json.Unmarshal(obj["emailId"], &emailID)
		// identityId, if supplied, must match this account's identity.
		var identityID string
		if json.Unmarshal(obj["identityId"], &identityID) == nil && identityID != "" && identityID != validIdentity {
			notCreated[cid] = map[string]any{"type": "invalidProperties", "properties": []string{"identityId"}}
			continue
		}
		// Envelope: {mailFrom:{email}, rcptTo:[{email}...]}.
		var env struct {
			MailFrom struct {
				Email string `json:"email"`
			} `json:"mailFrom"`
			RcptTo []struct {
				Email string `json:"email"`
			} `json:"rcptTo"`
		}
		if raw, ok := obj["envelope"]; ok {
			_ = json.Unmarshal(raw, &env)
		}

		// Read the referenced message body (any row of the email group carries it).
		var raw []byte
		rerr := acc.Tx(ctx, func(tx store.Tx) error {
			group, ok := s.emailGroup(tx, acc, emailID)
			if !ok {
				return errNotFoundJMAP
			}
			br := acc.MessageReader(group[0])
			defer br.Close()
			var e error
			raw, e = io.ReadAll(br)
			return e
		})
		if rerr != nil {
			notCreated[cid] = map[string]any{"type": "invalidProperties", "properties": []string{"emailId"}}
			continue
		}

		var rcpts []string
		for _, r := range env.RcptTo {
			rcpts = append(rcpts, r.Email)
		}
		if len(rcpts) == 0 {
			notCreated[cid] = map[string]any{"type": "invalidProperties", "properties": []string{"envelope"}}
			continue
		}

		// Authz: the envelope MailFrom must belong to the authenticated account.
		// Without this check any authenticated account could send as any address
		// (cross-tenant identity forgery), abusing the server's IP/DKIM
		// reputation. Fall back to the authenticated login when MailFrom is empty.
		mailFrom := env.MailFrom.Email
		if mailFrom == "" {
			mailFrom = login
		}
		if !s.senderOwnedBy(ctx, scope, acc, mailFrom) {
			notCreated[cid] = map[string]any{"type": "forbiddenFrom", "description": "envelope mailFrom is not an address of the authenticated account"}
			continue
		}

		if _, err := s.Submission.Submit(ctx, scope.Tenant().ID, acc.ID(), mailFrom, rcpts, raw); err != nil {
			notCreated[cid] = map[string]any{"type": "serverFail", "description": err.Error()}
			continue
		}
		created[cid] = map[string]any{
			"id":             "S" + cid,
			"undoStatus":     "final",
			"sendAt":         nil,
			"deliveryStatus": nil,
		}
	}

	newState, _ := accountState(ctx, acc)
	return "EmailSubmission/set", map[string]any{
		"accountId":  strconv.FormatInt(acc.ID(), 10),
		"oldState":   "",
		"newState":   newState,
		"created":    created,
		"notCreated": notCreated,
	}
}

// errNotFoundJMAP marks a referenced object as absent within a Tx closure.
var errNotFoundJMAP = errNo("not found")

// senderOwnedBy reports whether the envelope mailFrom address belongs to the
// authenticated account. Empty (null return-path) is not a valid submission
// sender here. It resolves the address through the authenticated tenant scope
// and compares the resulting account id, so a client cannot send as an address
// it does not own (cross-account/tenant identity forgery).
func (s *Server) senderOwnedBy(ctx context.Context, scope directory.TenantScope, acc store.Account, mailFrom string) bool {
	if mailFrom == "" {
		return false
	}
	addr, err := smtp.ParseAddress(mailFrom)
	if err != nil {
		return false
	}
	owner, err := scope.AccountForAddress(ctx, addr.Path())
	if err != nil {
		return false
	}
	return owner.ID() == acc.ID()
}

// Identity/get (RFC 8621 §6): return the sending identities available to the
// authenticated login. octo-mail models one identity per account — the login's own
// address — which EmailSubmission/set validates mailFrom against.
func (s *Server) identityGet(ctx context.Context, acc store.Account, login string, inv invocation) (string, any) {
	var ids []string
	haveFilter := json.Unmarshal(inv.args["ids"], &ids) == nil && inv.args["ids"] != nil

	id := "I" + strconv.FormatInt(acc.ID(), 10)
	identity := map[string]any{
		"id":            id,
		"name":          login,
		"email":         login,
		"replyTo":       nil,
		"bcc":           nil,
		"textSignature": "",
		"htmlSignature": "",
		"mayDelete":     false,
	}

	var list []map[string]any
	var notFound []string
	if haveFilter {
		for _, want := range ids {
			if want == id {
				list = append(list, identity)
			} else {
				notFound = append(notFound, want)
			}
		}
	} else {
		list = append(list, identity)
	}

	state, _ := accountState(ctx, acc)
	res := map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"state":     state,
		"list":      emptyList(list),
	}
	if notFound != nil {
		res["notFound"] = notFound
	}
	return "Identity/get", res
}

// Email/copy (RFC 8621 §5.4): within the authenticated account, copy referenced
// emails into another mailbox by re-delivering the source message body. octo-mail's
// one-mailbox-per-email model means a copy is a new Email object; the source is
// left intact (onSuccessDestroyOriginal not honored — reported per-id if set).
func (s *Server) emailCopy(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	// Cross-account copy (fromAccountId != accountId) is not supported: the
	// tenant scope yields no handle to another account's messages by design.
	var fromAccountID string
	_ = json.Unmarshal(inv.args["fromAccountId"], &fromAccountID)
	if fromAccountID != "" && fromAccountID != strconv.FormatInt(acc.ID(), 10) {
		return "error", map[string]any{"type": "fromAccountNotFound"}
	}

	var create map[string]map[string]json.RawMessage
	_ = json.Unmarshal(inv.args["create"], &create)

	created := map[string]any{}
	notCreated := map[string]any{}

	for cid, obj := range create {
		var srcID string
		_ = json.Unmarshal(obj["id"], &srcID)
		if _, ok := parseEmailGroupID(srcID); !ok {
			notCreated[cid] = map[string]any{"type": "notFound"}
			continue
		}
		// Resolve the target mailbox: first key of mailboxIds.
		target := ""
		var mids map[string]bool
		if json.Unmarshal(obj["mailboxIds"], &mids) == nil {
			for id := range mids {
				if n, e := strconv.ParseInt(id, 10, 64); e == nil {
					if name, ok := s.mailboxNameByID(ctx, acc, n); ok {
						target = name
						break
					}
				}
			}
		}
		if target == "" {
			notCreated[cid] = map[string]any{"type": "invalidProperties", "properties": []string{"mailboxIds"}}
			continue
		}

		// Read the source body (any group row), then re-deliver as a NEW email into
		// the target mailbox (Email/copy produces a distinct Email object).
		var raw []byte
		rerr := acc.Tx(ctx, func(tx store.Tx) error {
			group, ok := s.emailGroup(tx, acc, srcID)
			if !ok {
				return errNotFoundJMAP
			}
			br := acc.MessageReader(group[0])
			defer br.Close()
			var e error
			raw, e = io.ReadAll(br)
			return e
		})
		if rerr != nil {
			notCreated[cid] = map[string]any{"type": "notFound"}
			continue
		}

		m := &store.Message{}
		var kw map[string]bool
		if json.Unmarshal(obj["keywords"], &kw) == nil {
			applyJMAPKeywords(m, kw)
		}
		if _, err := acc.DeliverMailbox(target, m, memBlob(raw)); err != nil {
			if err == store.ErrOverQuota {
				notCreated[cid] = map[string]any{"type": "overQuota"}
			} else {
				notCreated[cid] = map[string]any{"type": "serverFail", "description": err.Error()}
			}
			continue
		}
		created[cid] = map[string]any{
			"id":         emailID(*m),
			"threadId":   "",
			"mailboxIds": map[string]bool{strconv.FormatInt(m.MailboxID, 10): true},
			"size":       m.Size,
		}
	}

	state, _ := accountState(ctx, acc)
	return "Email/copy", map[string]any{
		"fromAccountId": strconv.FormatInt(acc.ID(), 10),
		"accountId":     strconv.FormatInt(acc.ID(), 10),
		"oldState":      "",
		"newState":      state,
		"created":       created,
		"notCreated":    notCreated,
	}
}

type errNo string

func (e errNo) Error() string { return string(e) }

// searchSnippetGet implements SearchSnippet/get (RFC 8621 §5.6): for each
// requested emailId, return a subject + preview snippet with the filter's search
// term highlighted by <mark>...</mark>. The snippet is a window of the text body
// around the first match; if the term is absent from the body but present in the
// subject, only the subject is highlighted. This is what a JMAP client renders as
// the bold search-hit context under each result row.
func (s *Server) searchSnippetGet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var ids []string
	_ = json.Unmarshal(inv.args["emailIds"], &ids)
	filt := parseEmailFilter(inv.args["filter"])
	term := strings.TrimSpace(filt.text)

	var list []map[string]any
	var notFound []string
	err := acc.Tx(ctx, func(tx store.Tx) error {
		for _, id := range ids {
			group, ok := s.emailGroup(tx, acc, id)
			if !ok {
				notFound = append(notFound, id)
				continue
			}
			br := acc.MessageReader(group[0])
			data, _ := io.ReadAll(br)
			br.Close()

			subject, body := subjectAndText(data)
			snip := map[string]any{
				"emailId": id,
				"subject": highlight(subject, term),
				"preview": snippetAround(body, term),
			}
			list = append(list, snip)
		}
		return nil
	})
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	if list == nil {
		list = []map[string]any{}
	}
	return "SearchSnippet/get", map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"list":      list,
		"notFound":  notFound,
	}
}

// subjectAndText returns the message subject and the concatenated text/* body.
func subjectAndText(data []byte) (subject, body string) {
	part, _ := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if part.Envelope != nil {
		subject = part.Envelope.Subject
	}
	bv := map[string]any{}
	collectBodyValues(&part, "1", data, bv)
	var b strings.Builder
	for _, v := range bv {
		if m, ok := v.(map[string]any); ok {
			if txt, ok := m["value"].(string); ok {
				b.WriteString(txt)
				b.WriteString(" ")
			}
		}
	}
	return subject, b.String()
}

// snippetAround returns a window of text around the first case-insensitive match
// of term, with every occurrence wrapped in <mark>...</mark>. With no term or no
// match it returns a leading excerpt (highlighted where possible).
func snippetAround(text, term string) string {
	text = collapseSpace(text)
	if term == "" {
		return htmlEscape(excerpt(text, 0, 200))
	}
	idx := indexFold(text, term)
	if idx < 0 {
		return htmlEscape(excerpt(text, 0, 200))
	}
	// Window: ~40 chars before the match, ~160 after. Snap to rune boundaries so
	// a multibyte character is never sliced mid-sequence.
	start := alignRune(text, idx-40)
	end := alignRune(text, start+200)
	window := text[start:end]
	prefix := ""
	if start > 0 {
		prefix = "…"
	}
	suffix := ""
	if end < len(text) {
		suffix = "…"
	}
	return prefix + highlight(window, term) + suffix
}

// highlight wraps every case-insensitive occurrence of term in text with
// <mark>...</mark>, HTML-escaping the surrounding text. Returns escaped text
// unchanged when term is empty or absent.
func highlight(text, term string) string {
	if term == "" {
		return htmlEscape(text)
	}
	var b strings.Builder
	rest := text
	for {
		i := indexFold(rest, term)
		if i < 0 {
			b.WriteString(htmlEscape(rest))
			break
		}
		b.WriteString(htmlEscape(rest[:i]))
		b.WriteString("<mark>")
		b.WriteString(htmlEscape(rest[i : i+len(term)]))
		b.WriteString("</mark>")
		rest = rest[i+len(term):]
	}
	return b.String()
}

// indexFold returns the index of the first case-insensitive occurrence of sub in
// s, or -1. ASCII-fold, which suffices for snippet matching.
func indexFold(s, sub string) int {
	if sub == "" {
		return 0
	}
	ls, lsub := strings.ToLower(s), strings.ToLower(sub)
	return strings.Index(ls, lsub)
}

func excerpt(s string, start, n int) string {
	start = alignRune(s, start)
	end := alignRune(s, start+n)
	return s[start:end]
}

// alignRune clamps i into [0,len(s)] and advances it to the next UTF-8 rune
// boundary, so slicing s at the result never cuts a multibyte rune.
func alignRune(s string, i int) int {
	if i <= 0 {
		return 0
	}
	if i >= len(s) {
		return len(s)
	}
	for i < len(s) && s[i]&0xC0 == 0x80 { // continuation byte: move forward
		i++
	}
	return i
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// vacationGet implements VacationResponse/get (RFC 8621 §8): a singleton object
// (id "singleton") holding the account's auto-reply configuration.
func (s *Server) vacationGet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	v, _, err := acc.VacationGet(ctx)
	if err != nil {
		return "error", map[string]any{"type": "serverFail", "description": err.Error()}
	}
	obj := map[string]any{
		"id":        "singleton",
		"isEnabled": v.Enabled,
		"subject":   nilIfEmpty(v.Subject),
		"textBody":  nilIfEmpty(v.TextBody),
		"htmlBody":  nilIfEmpty(v.HTMLBody),
		"fromDate":  jmapDate(v.FromDate),
		"toDate":    jmapDate(v.ToDate),
	}
	st, _ := accountState(ctx, acc)
	return "VacationResponse/get", map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"state":     st,
		"list":      []map[string]any{obj},
		"notFound":  []string{},
	}
}

// vacationSet implements VacationResponse/set: only the singleton may be updated.
func (s *Server) vacationSet(ctx context.Context, acc store.Account, inv invocation) (string, any) {
	var update map[string]map[string]json.RawMessage
	_ = json.Unmarshal(inv.args["update"], &update)

	updated := map[string]any{}
	notUpdated := map[string]any{}
	for id, patch := range update {
		if id != "singleton" {
			notUpdated[id] = map[string]any{"type": "notFound"}
			continue
		}
		cur, _, err := acc.VacationGet(ctx)
		if err != nil {
			return "error", map[string]any{"type": "serverFail", "description": err.Error()}
		}
		applyVacationPatch(&cur, patch)
		if err := acc.VacationSet(ctx, cur); err != nil {
			return "error", map[string]any{"type": "serverFail", "description": err.Error()}
		}
		updated[id] = nil
	}

	st, _ := accountState(ctx, acc)
	return "VacationResponse/set", map[string]any{
		"accountId":  strconv.FormatInt(acc.ID(), 10),
		"oldState":   "",
		"newState":   st,
		"updated":    updated,
		"notUpdated": notUpdated,
	}
}

func applyVacationPatch(v *store.VacationResponse, patch map[string]json.RawMessage) {
	for k, raw := range patch {
		switch k {
		case "isEnabled":
			_ = json.Unmarshal(raw, &v.Enabled)
		case "subject":
			v.Subject = jsonString(raw)
		case "textBody":
			v.TextBody = jsonString(raw)
		case "htmlBody":
			v.HTMLBody = jsonString(raw)
		case "fromDate":
			v.FromDate = parseJMAPDate(jsonString(raw))
		case "toDate":
			v.ToDate = parseJMAPDate(jsonString(raw))
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jmapDate(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func parseJMAPDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return t
	}
	return time.Time{}
}

// jsonString unmarshals a JSON string value, returning "" for null/non-strings.
func jsonString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}
