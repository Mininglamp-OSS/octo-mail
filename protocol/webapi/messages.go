package webapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	moxmessage "github.com/mjl-/mox/message"
)

// maxListLimit caps the page size of a single list request, so an absent/zero/
// oversized ?limit can't return the whole account in one response.
const maxListLimit = 1000

// messageSummary is the list-view shape of a message.
type messageSummary struct {
	ID         string   `json:"id"`
	ThreadID   string   `json:"threadId,omitempty"`
	Mailbox    string   `json:"mailbox"`
	Subject    string   `json:"subject"`
	From       string   `json:"from"`
	To         []string `json:"to"`
	Preview    string   `json:"preview"`
	ReceivedAt string   `json:"receivedAt"`
	Size       int64    `json:"size"`
	Keywords   []string `json:"keywords"`
	Unread     bool     `json:"unread"`
}

// messageDetail adds parsed bodies to the summary.
type messageDetail struct {
	messageSummary
	Cc       []string `json:"cc,omitempty"`
	BodyText string   `json:"bodyText,omitempty"`
	BodyHTML string   `json:"bodyHtml,omitempty"`
}

// GET /webapi/v0/messages?mailbox=&search=&limit=&offset=
func (s *Server) listMessages(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	q := r.URL.Query()
	mailbox := q.Get("mailbox")
	search := q.Get("search")
	limit := atoiDefault(q.Get("limit"), 50)
	offset := atoiDefault(q.Get("offset"), 0)
	// Clamp the page size: a 0/negative/oversized limit (e.g. ?limit=0 or a huge
	// value) must not return the whole account in one response. Clients page with
	// offset for more.
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}
	if offset < 0 {
		offset = 0
	}

	var out []messageSummary
	var total int
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		// Build the filtered, email-deduped query once; Count gives the true total,
		// then the same filter is sorted + paged in SQL. No whole-account load, no
		// per-row body parse (summarize reads the projection columns).
		filter := func() store.MessageQuery {
			mq := tx.QueryMessage().DistinctEmail()
			if search != "" {
				mq = mq.FilterFTS(search)
			}
			return mq
		}
		if mailbox != "" {
			mb, e := a.acc.MailboxFind(tx, mailbox)
			if e != nil {
				return e
			}
			if mb == nil {
				return errStatus(http.StatusNotFound, "not_found", "no such mailbox")
			}
			// Re-apply the mailbox filter on each builder instance below.
			base := filter
			filter = func() store.MessageQuery { return base().FilterMailbox(mb.ID) }
		}
		n, e := filter().Count()
		if e != nil {
			return e
		}
		total = n
		msgs, e := filter().SortReceivedDesc().Limit(limit).Offset(offset).List()
		if e != nil {
			return e
		}
		mbNames := mailboxNames(tx, a.acc)
		for _, m := range msgs {
			out = append(out, summarize(a.acc, m, mbNames))
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if out == nil {
		out = []messageSummary{}
	}
	return http.StatusOK, map[string]any{"messages": out, "total": total, "offset": offset, "limit": limit}, nil
}

// GET /webapi/v0/messages/{id}
func (s *Server) getMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	var detail messageDetail
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		m := msgs[0]
		mbNames := mailboxNames(tx, a.acc)
		detail.messageSummary = summarize(a.acc, m, mbNames)
		// Parse bodies + cc from the raw message.
		br := a.acc.MessageReader(m)
		data, _ := io.ReadAll(br)
		br.Close()
		text, html, cc := parseBodies(data)
		detail.BodyText, detail.BodyHTML, detail.Cc = text, html, cc
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, detail, nil
}

// GET /webapi/v0/messages/{id}/raw
func (s *Server) rawMessage(ctx context.Context, a authCtx, r *http.Request) (store.BlobReader, error) {
	id := r.PathValue("id")
	var br store.BlobReader
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br = a.acc.MessageReader(msgs[0])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return br, nil
}

// sendRequest is the POST /messages body.
type sendRequest struct {
	To          []string     `json:"to"`
	Cc          []string     `json:"cc,omitempty"`
	Bcc         []string     `json:"bcc,omitempty"`
	Subject     string       `json:"subject"`
	Text        string       `json:"text,omitempty"`
	HTML        string       `json:"html,omitempty"`
	Attachments []attachment `json:"attachments,omitempty"`
}

// POST /webapi/v0/messages  (send)
func (s *Server) sendMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Submission == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	var req sendRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	if len(req.To) == 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_body", "at least one recipient in 'to' is required")
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	rcpts := allRecipients(req.To, req.Cc, req.Bcc)
	ids, err := s.Submission.Submit(ctx, a.scope.Tenant().ID, a.acc.ID(), a.login, rcpts, raw)
	if err != nil {
		return 0, nil, internalErr("submit_failed", err)
	}
	return http.StatusAccepted, map[string]any{"submissionIds": ids}, nil
}

// replyRequest is the POST /messages/{id}/reply[-all] body.
type replyRequest struct {
	Text        string       `json:"text,omitempty"`
	HTML        string       `json:"html,omitempty"`
	Attachments []attachment `json:"attachments,omitempty"`
}

func (s *Server) replyMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	return s.reply(ctx, a, r, false)
}
func (s *Server) replyAllMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	return s.reply(ctx, a, r, true)
}

func (s *Server) reply(ctx context.Context, a authCtx, r *http.Request, all bool) (int, any, error) {
	if s.Submission == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	id := r.PathValue("id")
	var req replyRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	var (
		to, cc     []string
		subject    string
		inReplyTo  string
		references []string
	)
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br := a.acc.MessageReader(msgs[0])
		data, _ := io.ReadAll(br)
		br.Close()
		env := parseEnvelope(data)
		to, cc = replyRecipients(env, a.login, all)
		subject = ensurePrefix(env.subject, "Re: ")
		inReplyTo = env.messageID
		references = append(env.references, env.messageID)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if len(to) == 0 {
		return 0, nil, errStatus(http.StatusUnprocessableEntity, "no_recipients", "original has no reply recipient")
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: to, Cc: cc, Subject: subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
		InReplyTo: inReplyTo, References: references,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	ids, err := s.Submission.Submit(ctx, a.scope.Tenant().ID, a.acc.ID(), a.login, allRecipients(to, cc, nil), raw)
	if err != nil {
		return 0, nil, internalErr("submit_failed", err)
	}
	return http.StatusAccepted, map[string]any{"submissionIds": ids}, nil
}

// forwardRequest is the POST /messages/{id}/forward body.
type forwardRequest struct {
	To          []string     `json:"to"`
	Text        string       `json:"text,omitempty"`
	Attachments []attachment `json:"attachments,omitempty"`
}

func (s *Server) forwardMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Submission == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	id := r.PathValue("id")
	var req forwardRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	if len(req.To) == 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_body", "at least one recipient in 'to' is required")
	}
	var subject, quoted string
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br := a.acc.MessageReader(msgs[0])
		data, _ := io.ReadAll(br)
		br.Close()
		env := parseEnvelope(data)
		text, _, _ := parseBodies(data)
		subject = ensurePrefix(env.subject, "Fwd: ")
		quoted = "---------- Forwarded message ----------\r\nFrom: " + env.from + "\r\nSubject: " + env.subject + "\r\n\r\n" + text
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	body := req.Text
	if body != "" {
		body += "\r\n\r\n"
	}
	body += quoted
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Subject: subject, Text: body, Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	ids, err := s.Submission.Submit(ctx, a.scope.Tenant().ID, a.acc.ID(), a.login, req.To, raw)
	if err != nil {
		return 0, nil, internalErr("submit_failed", err)
	}
	return http.StatusAccepted, map[string]any{"submissionIds": ids}, nil
}

// patchRequest updates flags and/or moves the message.
type patchRequest struct {
	AddKeywords    []string `json:"addKeywords,omitempty"`
	RemoveKeywords []string `json:"removeKeywords,omitempty"`
}

// PATCH /webapi/v0/messages/{id}
func (s *Server) patchMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	var req patchRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	if len(req.AddKeywords) == 0 && len(req.RemoveKeywords) == 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_body", "provide addKeywords and/or removeKeywords")
	}
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		// Apply to every row in the group (message may span mailboxes).
		for i := range msgs {
			m := msgs[i]
			for _, k := range req.AddKeywords {
				setFlag(&m, k, true)
			}
			for _, k := range req.RemoveKeywords {
				setFlag(&m, k, false)
			}
			if e := tx.Update(&m); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"updated": id}, nil
}

// DELETE /webapi/v0/messages/{id}
func (s *Server) deleteMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		// Expunge each row from its mailbox.
		for i := range msgs {
			m := msgs[i]
			mb, e := mailboxByID(tx, a.acc, m.MailboxID)
			if e != nil {
				return e
			}
			if _, _, e := a.acc.MessageRemove(tx, 0, mb, store.RemoveOpts{Expunge: true}, m); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

// --- message helpers ---

func summarize(acc store.Account, m store.Message, mbNames map[int64]string) messageSummary {
	// Prefer the denormalized summary columns (H13); fall back to an on-the-fly
	// body parse only for rows the projection hasn't folded yet (recently
	// delivered), so the common case does no blob read/MIME parse.
	subject, from, to, preview := m.Subject, m.FromAddr, splitAddrs(m.ToAddrs), m.Preview
	if !m.SummaryFolded {
		br := acc.MessageReader(m)
		data, _ := io.ReadAll(br)
		br.Close()
		env := parseEnvelope(data)
		subject, from, to, preview = env.subject, env.from, env.to, previewText(data)
	}
	sum := messageSummary{
		ID:       emailID(m),
		Mailbox:  mbNames[m.MailboxID],
		Subject:  subject,
		From:     from,
		To:       to,
		Preview:  preview,
		Size:     m.Size,
		Keywords: m.Flags.IMAPFlags(m.Keywords),
		Unread:   !m.Flags.Seen,
	}
	if sum.To == nil {
		sum.To = []string{}
	}
	if sum.Keywords == nil {
		sum.Keywords = []string{}
	}
	if m.ThreadID != 0 {
		sum.ThreadID = "T" + strconv.FormatInt(m.ThreadID, 10)
	}
	if !m.Received.IsZero() {
		sum.ReceivedAt = m.Received.UTC().Format("2006-01-02T15:04:05Z")
	}
	return sum
}

// splitAddrs splits the space-joined to_addrs column back into a list.
func splitAddrs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func mailboxNames(tx store.Tx, acc store.Account) map[int64]string {
	out := map[int64]string{}
	mbs, err := tx.QueryMailbox().List()
	if err == nil {
		for _, mb := range mbs {
			out[mb.ID] = mb.Name
		}
	}
	return out
}

func mailboxByID(tx store.Tx, acc store.Account, id int64) (*store.Mailbox, error) {
	mbs, err := tx.QueryMailbox().List()
	if err != nil {
		return nil, err
	}
	for i := range mbs {
		if mbs[i].ID == id {
			return &mbs[i], nil
		}
	}
	return nil, errStatus(http.StatusNotFound, "not_found", "mailbox not found")
}

// envelope holds parsed header fields we surface.
type envelope struct {
	subject    string
	from       string
	to         []string
	cc         []string
	messageID  string
	references []string
}

func parseEnvelope(data []byte) envelope {
	var e envelope
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if err != nil && part.Envelope == nil {
		return e
	}
	if env := part.Envelope; env != nil {
		e.subject = env.Subject
		if len(env.From) > 0 {
			e.from = env.From[0].User + "@" + env.From[0].Host
		}
		for _, a := range env.To {
			e.to = append(e.to, a.User+"@"+a.Host)
		}
		for _, a := range env.CC {
			e.cc = append(e.cc, a.User+"@"+a.Host)
		}
		e.messageID = env.MessageID
	}
	// References chain: read the raw References header (mox's Envelope has no
	// References field), falling back to In-Reply-To. Threading needs the full
	// chain, not just the immediate parent.
	if h, herr := part.Header(); herr == nil {
		if refs := strings.Fields(h.Get("References")); len(refs) > 0 {
			e.references = refs
		}
	}
	if len(e.references) == 0 && part.Envelope != nil && part.Envelope.InReplyTo != "" {
		e.references = append(e.references, part.Envelope.InReplyTo)
	}
	return e
}

// parseBodies returns (text, html, cc) parsed from the raw message.
func parseBodies(data []byte) (text, html string, cc []string) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if err != nil && part.Envelope == nil {
		return "", "", nil
	}
	if part.Envelope != nil {
		for _, a := range part.Envelope.CC {
			cc = append(cc, a.User+"@"+a.Host)
		}
	}
	var walk func(p *moxmessage.Part)
	walk = func(p *moxmessage.Part) {
		if len(p.Parts) > 0 {
			for i := range p.Parts {
				walk(&p.Parts[i])
			}
			return
		}
		if !strings.EqualFold(p.MediaType, "TEXT") && p.MediaType != "" {
			return
		}
		rd := p.Reader()
		if rd == nil {
			return
		}
		b, _ := io.ReadAll(rd)
		if strings.EqualFold(p.MediaSubType, "HTML") {
			if html == "" {
				html = string(b)
			}
		} else if text == "" {
			text = string(b)
		}
	}
	walk(&part)
	return text, html, cc
}

func previewText(data []byte) string {
	text, html, _ := parseBodies(data)
	s := text
	if s == "" {
		s = stripTags(html)
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 140 {
		s = s[:140]
	}
	return s
}

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

func replyRecipients(env envelope, self string, all bool) (to, cc []string) {
	if env.from != "" {
		to = append(to, env.from)
	}
	if all {
		for _, a := range append(append([]string{}, env.to...), env.cc...) {
			if a != "" && !strings.EqualFold(a, self) && !containsFold(to, a) && !containsFold(cc, a) {
				cc = append(cc, a)
			}
		}
	}
	return to, cc
}

func ensurePrefix(s, prefix string) string {
	if strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
		return s
	}
	return prefix + s
}

func allRecipients(to, cc, bcc []string) []string {
	out := append([]string{}, to...)
	out = append(out, cc...)
	out = append(out, bcc...)
	return out
}

func containsFold(ss []string, s string) bool {
	for _, x := range ss {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// setFlag sets a known system flag (\Seen, $Junk, ...) or a free-form keyword on
// the message via the canonical Flags parser.
func setFlag(m *store.Message, name string, v bool) {
	if m.Flags.SetByName(name, v) {
		return
	}
	// Free-form keyword.
	if v {
		if !containsFold(m.Keywords, name) {
			m.Keywords = append(m.Keywords, name)
		}
	} else {
		out := m.Keywords[:0]
		for _, k := range m.Keywords {
			if !strings.EqualFold(k, name) {
				out = append(out, k)
			}
		}
		m.Keywords = out
	}
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}
