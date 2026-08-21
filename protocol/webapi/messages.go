package webapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreplychain"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	moxmessage "github.com/mjl-/mox/message"
	moxsmtp "github.com/mjl-/mox/smtp"
)

// maxListLimit caps the page size of a single list request, so an absent/zero/
// oversized ?limit can't return the whole account in one response.
const maxListLimit = 1000

type messageSubmitter interface {
	SubmitForMessage(ctx context.Context, tenantID, accountID, messageID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error)
}

// messageSummary is the list-view shape of a message.
type messageSummary struct {
	ID         string              `json:"id"`
	ThreadID   string              `json:"threadId,omitempty"`
	Mailbox    string              `json:"mailbox"`
	Subject    string              `json:"subject"`
	From       string              `json:"from"`
	To         []string            `json:"to"`
	Preview    string              `json:"preview"`
	ReceivedAt string              `json:"receivedAt"`
	Size       int64               `json:"size"`
	Keywords   []string            `json:"keywords"`
	Unread     bool                `json:"unread"`
	Delivery   *deliverySummary    `json:"delivery,omitempty"`
	Policy     *outboundPolicyInfo `json:"policy,omitempty"`
	AgentDraft *agentDraftInfo     `json:"agentDraft,omitempty"`
}

// messageDetail adds parsed bodies to the summary.
type messageDetail struct {
	messageSummary
	Cc                   []string             `json:"cc,omitempty"`
	Bcc                  []string             `json:"bcc,omitempty"`
	BodyText             string               `json:"bodyText,omitempty"`
	BodyHTML             string               `json:"bodyHtml,omitempty"`
	BodyTruncated        bool                 `json:"bodyTruncated,omitempty"`
	OriginalFrom         string               `json:"originalFrom,omitempty"`
	SentBy               string               `json:"sentBy,omitempty"`
	Attachments          []receivedAttachment `json:"attachments"`
	AttachmentsTruncated bool                 `json:"attachmentsTruncated,omitempty"`
}

// GET /webapi/v0/messages?mailbox=&search=&unread=&limit=&offset=
func (s *Server) listMessages(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	q := r.URL.Query()
	mailbox := q.Get("mailbox")
	search := q.Get("search")
	var unread *bool
	if values, ok := q["unread"]; ok {
		if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid_query", "unread must be true or false")
		}
		value, _ := strconv.ParseBool(values[0])
		unread = &value
	}
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
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		// Build the filtered, email-deduped query once; Count gives the true total,
		// then the same filter is sorted + paged in SQL. No whole-account load, no
		// per-row body parse (summarize reads the projection columns).
		filter := func() store.MessageQuery {
			mq := tx.QueryMessage().DistinctEmail()
			if unread != nil {
				mq = mq.FilterFlags(store.Flags{Seen: true}, store.Flags{Seen: !*unread})
			}
			if search != "" {
				mq = mq.FilterFTS(search)
			}
			return mq
		}
		if mailbox != "" {
			if strings.EqualFold(mailbox, "Starred") {
				base := filter
				filter = func() store.MessageQuery {
					return base().FilterKeyword("$flagged", true)
				}
			} else {
				mb, e := a.acc.MailboxFind(tx, mailbox)
				if e != nil {
					return e
				}
				if isEmptyRequiredMailbox(mailbox, mb) {
					return nil
				}
				if mb == nil {
					return errStatus(http.StatusNotFound, "not_found", "no such mailbox")
				}
				// Re-apply the mailbox filter on each builder instance below.
				base := filter
				filter = func() store.MessageQuery { return base().FilterMailbox(mb.ID) }
			}
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
			out = append(out, summarize(ctx, a.acc, m, mbNames))
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if out == nil {
		out = []messageSummary{}
	}
	messageIDs := make([]int64, 0, len(out))
	for _, message := range out {
		if id, ok := parseEmailID(message.ID); ok {
			messageIDs = append(messageIDs, id)
		}
	}
	deliveries := map[int64][]store.OutboundDelivery{}
	if tracked, ok := a.acc.(store.OutboundDeliveryStore); ok {
		deliveries, err = tracked.OutboundDeliveriesForMessages(ctx, messageIDs)
		if err != nil {
			return 0, nil, err
		}
	}
	for i := range out {
		if id, ok := parseEmailID(out[i].ID); ok {
			out[i].Delivery = summarizeDelivery(deliveries[id])
		}
	}
	if policies, ok := a.acc.(store.OutboundPolicyDraftStore); ok {
		items, err := policies.OutboundPolicyDraftsForMessages(ctx, messageIDs)
		if err != nil {
			return 0, nil, err
		}
		for i := range out {
			if id, ok := parseEmailID(out[i].ID); ok {
				if draft, exists := items[id]; exists {
					policy := outboundPolicyProjection(draft, out[i].Subject)
					out[i].Policy = &policy
				}
			}
		}
	}
	if drafts, ok := a.acc.(store.AgentOutboundDraftStore); ok {
		items, err := drafts.AgentOutboundDraftsForMessages(ctx, messageIDs)
		if err != nil {
			return 0, nil, err
		}
		for i := range out {
			if id, ok := parseEmailID(out[i].ID); ok {
				if draft, exists := items[id]; exists {
					projection := agentDraftProjection(draft, out[i].Subject, out[i].From, numericThreadID(out[i].ThreadID))
					out[i].AgentDraft = &projection
				}
			}
		}
	}
	return http.StatusOK, map[string]any{"messages": out, "total": total, "offset": offset, "limit": limit}, nil
}

// GET /webapi/v0/messages/{id}
func (s *Server) getMessage(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	ruleRecipients := ruleRecipientAddresses(ctx, a)
	var detail messageDetail
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		m := msgs[0]
		mbNames := mailboxNames(tx, a.acc)
		detail.messageSummary = summarize(ctx, a.acc, m, mbNames)
		// Parse bodies + cc from the raw message.
		br := a.acc.MessageReader(ctx, m)
		data, _ := io.ReadAll(br)
		br.Close()
		text, html, cc, bodyTruncated := parseBodiesWithTruncation(data)
		envelope := parseEnvelope(data, s.RuleMetadata, ruleRecipients)
		detail.BodyText, detail.BodyHTML, detail.Cc = text, html, cc
		detail.BodyTruncated = bodyTruncated
		detail.Bcc = envelope.bcc
		detail.OriginalFrom, detail.SentBy = envelope.originalFrom, envelope.sentBy
		detail.Attachments, detail.AttachmentsTruncated = parseAttachments(data)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if messageID, ok := parseEmailID(id); ok {
		if tracked, ok := a.acc.(store.OutboundDeliveryStore); ok {
			deliveries, err := tracked.OutboundDeliveries(ctx, messageID)
			if err != nil {
				return 0, nil, err
			}
			detail.Delivery = summarizeDelivery(deliveries)
		}
		if policies, ok := a.acc.(store.OutboundPolicyDraftStore); ok {
			items, err := policies.OutboundPolicyDraftsForMessages(ctx, []int64{messageID})
			if err != nil {
				return 0, nil, err
			}
			if draft, exists := items[messageID]; exists {
				policy := outboundPolicyProjection(draft, detail.Subject)
				detail.Policy = &policy
			}
		}
		if drafts, ok := a.acc.(store.AgentOutboundDraftStore); ok {
			items, err := drafts.AgentOutboundDraftsForMessages(ctx, []int64{messageID})
			if err != nil {
				return 0, nil, err
			}
			if draft, exists := items[messageID]; exists {
				projection := agentDraftProjection(draft, detail.Subject, detail.From, numericThreadID(detail.ThreadID))
				detail.AgentDraft = &projection
			}
		}
	}
	return http.StatusOK, detail, nil
}

// GET /webapi/v0/messages/{id}/raw
func (s *Server) rawMessage(ctx context.Context, a authCtx, r *http.Request) (store.BlobReader, error) {
	id := r.PathValue("id")
	var br store.BlobReader
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br = a.acc.MessageReader(ctx, msgs[0])
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
	policyRaw := raw
	if len(req.Bcc) > 0 && a.agentCredentialID > 0 && s.OutboundPolicy != nil {
		policyRaw, _, err = compose(composeInput{
			From: a.login, To: req.To, Cc: req.Cc, DraftBcc: req.Bcc, Subject: req.Subject,
			Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
		}, a.senderDomain())
		if err != nil {
			return 0, nil, err
		}
	}
	if err := s.enforceAgentOutboundPolicy(ctx, a, r, outboundpolicy.Intent{
		Source: outboundPolicySource(r), Operation: "mail.message.send",
		To: req.To, Cc: req.Cc, Bcc: req.Bcc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, AttachmentCount: len(req.Attachments),
	}, policyRaw); err != nil {
		return 0, nil, err
	}
	return s.submitComposedMessage(ctx, a, req.To, req.Cc, req.Bcc, raw)
}

func (s *Server) submitComposedMessage(ctx context.Context, a authCtx, to, cc, bcc []string, raw []byte) (int, any, error) {
	sent, ids, err := s.enqueueComposedMessage(ctx, a, to, cc, bcc, raw)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, map[string]any{
		"outcome": "accepted", "submissionIds": ids, "messageId": emailID(sent),
		"senderAddress": a.login,
	}, nil
}

func (s *Server) enqueueComposedMessage(ctx context.Context, a authCtx, to, cc, bcc []string, raw []byte) (store.Message, []int64, error) {
	if s.Submission == nil {
		return store.Message{}, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	rcpts := allRecipients(to, cc, bcc)
	sent, err := saveSentCopy(ctx, a.acc, raw)
	if err != nil {
		return store.Message{}, nil, internalErr("sent_copy_failed", err)
	}
	ids, err := s.Submission.SubmitForMessage(ctx, a.scope.Tenant().ID, a.acc.ID(), sent.EffectiveEmailID(), a.login, rcpts, raw)
	if err != nil {
		if submit.IsResultUnknown(err) {
			return sent, nil, submissionResultUnknownError(err)
		}
		s.cleanupFailedSubmissionSentCopy(ctx, a.acc, sent.EffectiveEmailID())
		return store.Message{}, nil, internalErr("submit_failed", err)
	}
	return sent, ids, nil
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
	automatic := isAgentAutomaticReply(a, r)
	var (
		to, cc                  []string
		subject                 string
		inReplyTo               string
		references              []string
		sourceRaw               []byte
		automaticIntentDigest   []byte
		automaticIdempotencyKey string
		trustedForward          rulemetadata.Metadata
		trustedForwardOK        bool
	)
	sourceRaw, err := readMessageBytes(ctx, a.acc, id)
	if err != nil {
		return 0, nil, err
	}
	env := parseEnvelope(sourceRaw, nil, nil)
	to, cc = replyRecipients(env, a.login, all)
	subject = ensurePrefix(env.subject, "Re: ")
	inReplyTo = env.messageID
	references = append(env.references, env.messageID)
	if len(to) == 0 {
		return 0, nil, errStatus(http.StatusUnprocessableEntity, "no_recipients", "original has no reply recipient")
	}
	if automatic {
		automaticIdempotencyKey = strings.TrimSpace(r.Header.Get(outboundIdempotencyHeader))
		sourceIdentity := id
		trustedForward, trustedForwardOK = s.trustedRuleForwardMetadata(ctx, a, sourceRaw)
		if trustedForwardOK {
			// A signed forwarding Message-ID identifies the same server-generated
			// message across repeated SMTP deliveries, while local Email ids do
			// not. Scope the internal key to the receiving account so one trusted
			// forward can trigger at most one automatic reply in that mailbox.
			sourceIdentity = trustedForward.MessageID
			automaticIdempotencyKey = scopedOutboundIdempotencyKey(
				a.acc.ID(), "trusted-rule-forward:"+trustedForward.MessageID,
			)
		}
		// Idempotency binds the caller's request, not server-generated transport
		// metadata or the final-chain notice appended below. A configuration
		// change must not turn a retry of an accepted request into a conflict.
		automaticIntentDigest = agentDraftIntentDigest("agent_automatic_reply", sourceIdentity, req)
	}
	messageID := ""
	trustedHeaders := map[string]string(nil)
	if isAgentAutomaticReply(a, r) {
		// RFC 3834 loop labelling is required independently of the optional OCTO
		// count-chain. A configured maximum of zero disables only the local count
		// limit; it must not make an Agent auto-reply look human-generated to the
		// receiving MTA.
		trustedHeaders = map[string]string{
			autoreplychain.HeaderSubmitted: autoreplychain.SubmittedAutoReplied,
		}
		if s.AutoReplyChain != nil {
			messageID, err = genMessageID(a.senderDomain())
			if err != nil {
				return 0, nil, internalErr("message_id_failed", err)
			}
			metadata, err := s.nextAutoReplyMetadata(ctx, a, id, sourceRaw, messageID, to[0], trustedForwardOK)
			if err != nil {
				return 0, nil, err
			}
			if s.AutoReplyChain.IsFinalCount(metadata.Count) {
				req.Text = autoreplychain.AppendFinalNotice(req.Text)
				if len(req.Text) > 100000 {
					return 0, nil, errStatus(http.StatusRequestEntityTooLarge, "automatic_reply_too_large", "final automatic reply exceeds the plain-text size limit")
				}
			}
			trustedHeaders = autoreplychain.Headers(metadata)
		}
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: to, Cc: cc, Subject: subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
		MessageID: messageID, InReplyTo: inReplyTo, References: references,
		TrustedHeaders: trustedHeaders,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	operation := "mail.message.reply"
	if all {
		operation = "mail.message.reply_all"
	}
	policyDedupe := outboundPolicyDedupe{}
	if trustedForwardOK {
		policyDedupe = outboundPolicyDedupe{
			requestKey:     automaticIdempotencyKey,
			sourceIdentity: trustedForward.MessageID,
		}
	}
	if err := s.enforceAgentOutboundPolicyWithDedupe(ctx, a, r, outboundpolicy.Intent{
		Source: outboundPolicySource(r), Operation: operation, SourceEmailID: id,
		To: to, Cc: cc, Subject: subject, Text: req.Text, HTML: req.HTML,
		AttachmentCount: len(req.Attachments),
	}, raw, policyDedupe); err != nil {
		return 0, nil, err
	}
	var automaticIntentClaimed bool
	if automatic {
		intent, claimed, err := s.claimAgentSendIntent(ctx, a, automaticIdempotencyKey, automaticIntentDigest)
		if err != nil {
			return 0, nil, err
		}
		if !claimed {
			return existingAgentSendIntentResult(a, intent)
		}
		automaticIntentClaimed = true
	}
	sent, err := saveSentCopy(ctx, a.acc, raw)
	if err != nil {
		if automaticIntentClaimed {
			s.abandonAgentSendIntent(ctx, a, automaticIdempotencyKey)
		}
		return 0, nil, internalErr("sent_copy_failed", err)
	}
	ids, err := s.Submission.SubmitForMessage(ctx, a.scope.Tenant().ID, a.acc.ID(), sent.EffectiveEmailID(), a.login, allRecipients(to, cc, nil), raw)
	if err != nil {
		if submit.IsResultUnknown(err) {
			if automaticIntentClaimed {
				return 0, nil, resultUnknownStatusError(
					"send_intent_result_unknown",
					"this automatic reply may have been accepted; inspect Sent and do not retry automatically",
					err,
				)
			}
			return 0, nil, submissionResultUnknownError(err)
		}
		s.cleanupFailedSubmissionSentCopy(ctx, a.acc, sent.EffectiveEmailID())
		if automaticIntentClaimed {
			s.abandonAgentSendIntent(ctx, a, automaticIdempotencyKey)
		}
		return 0, nil, internalErr("submit_failed", err)
	}
	if automaticIntentClaimed {
		s.completeAgentSendIntent(ctx, a, automaticIdempotencyKey, sent.EffectiveEmailID(), ids)
	}
	return http.StatusAccepted, map[string]any{
		"outcome": "accepted", "submissionIds": ids, "messageId": emailID(sent),
		"senderAddress": a.login,
	}, nil
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
	var subject, quoted, originalFrom string
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br := a.acc.MessageReader(ctx, msgs[0])
		data, _ := io.ReadAll(br)
		br.Close()
		env := parseEnvelope(data, nil, nil)
		text, _, _ := parseBodies(data)
		subject = ensurePrefix(env.subject, "Fwd: ")
		originalFrom = env.from
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
		OriginalFrom: originalFrom, SentBy: a.login,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	if err := s.enforceAgentOutboundPolicy(ctx, a, r, outboundpolicy.Intent{
		Source: outboundPolicySource(r), Operation: "mail.message.forward", SourceEmailID: id,
		To: req.To, Subject: subject, Text: body, AttachmentCount: len(req.Attachments),
	}, raw); err != nil {
		return 0, nil, err
	}
	sent, err := saveSentCopy(ctx, a.acc, raw)
	if err != nil {
		return 0, nil, internalErr("sent_copy_failed", err)
	}
	ids, err := s.Submission.SubmitForMessage(ctx, a.scope.Tenant().ID, a.acc.ID(), sent.EffectiveEmailID(), a.login, req.To, raw)
	if err != nil {
		if submit.IsResultUnknown(err) {
			return 0, nil, submissionResultUnknownError(err)
		}
		s.cleanupFailedSubmissionSentCopy(ctx, a.acc, sent.EffectiveEmailID())
		return 0, nil, internalErr("submit_failed", err)
	}
	return http.StatusAccepted, map[string]any{
		"outcome": "accepted", "submissionIds": ids, "messageId": emailID(sent),
		"senderAddress": a.login,
	}, nil
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
	if a.agentCredentialID > 0 {
		for _, keywords := range [][]string{req.AddKeywords, req.RemoveKeywords} {
			for _, keyword := range keywords {
				if agentKeywordRequiresOwner(keyword) {
					return 0, nil, errStatus(http.StatusForbidden, "owner_required", "this Agent Mail keyword change must be completed by the human owner gateway")
				}
			}
		}
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

// agentKeywordRequiresOwner permits non-destructive progress markers and
// free-form keywords while keeping owner-controlled system state out of reach
// of an Agent credential. SetByName is the canonical parser for IMAP/JMAP flag
// aliases, so spellings such as \Deleted, $deleted, and DELETED stay equivalent.
func agentKeywordRequiresOwner(name string) bool {
	var flags store.Flags
	if !flags.SetByName(name, true) {
		return false
	}
	return !(flags.Seen || flags.Answered || flags.Flagged || flags.Forwarded)
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

func summarize(ctx context.Context, acc store.Account, m store.Message, mbNames map[int64]string) messageSummary {
	// Prefer the denormalized summary columns (H13); fall back to an on-the-fly
	// body parse only for rows the projection hasn't folded yet (recently
	// delivered), so the common case does no blob read/MIME parse.
	subject, from, to, preview := m.Subject, m.FromAddr, splitAddrs(m.ToAddrs), m.Preview
	if !m.SummaryFolded {
		br := acc.MessageReader(ctx, m)
		data, _ := io.ReadAll(br)
		br.Close()
		env := parseEnvelope(data, nil, nil)
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
	subject      string
	from         string
	replyTo      string
	to           []string
	cc           []string
	bcc          []string
	messageID    string
	references   []string
	originalFrom string
	sentBy       string
}

func parseEnvelope(data []byte, ruleAuthenticator *rulemetadata.Authenticator, expectedRecipients []string) envelope {
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
		for _, a := range env.BCC {
			e.bcc = append(e.bcc, a.User+"@"+a.Host)
		}
		if len(env.ReplyTo) > 0 {
			e.replyTo = env.ReplyTo[0].User + "@" + env.ReplyTo[0].Host
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
		if ruleAuthenticator != nil {
			if metadata, ok := ruleAuthenticator.VerifyAny(data, expectedRecipients, time.Now()); ok {
				e.originalFrom = validAttributionAddress(metadata.OriginalFrom)
				e.sentBy = validAttributionAddress(metadata.SentBy)
			}
		}
	}
	if len(e.references) == 0 && part.Envelope != nil && part.Envelope.InReplyTo != "" {
		e.references = append(e.references, part.Envelope.InReplyTo)
	}
	return e
}

func validAttributionAddress(value string) string {
	value = strings.TrimSpace(value)
	address, err := moxsmtp.ParseAddress(value)
	if err != nil {
		return ""
	}
	return address.String()
}

const maxRenderableHTMLBytes = 128 * 1024

// parseBodies returns (text, html, cc) parsed from the raw message.
func parseBodies(data []byte) (text, html string, cc []string) {
	text, html, cc, _ = parseBodiesWithTruncation(data)
	return text, html, cc
}

// parseBodiesWithTruncation returns one eligible HTML body when it fits the
// inline rendering limit. Oversized or multiple HTML bodies are omitted so the
// client can offer the complete raw message instead.
func parseBodiesWithTruncation(data []byte) (text, html string, cc []string, bodyTruncated bool) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if err != nil && part.Envelope == nil {
		return "", "", nil, false
	}
	if part.Envelope != nil {
		for _, a := range part.Envelope.CC {
			cc = append(cc, a.User+"@"+a.Host)
		}
	}
	var htmlParts []*moxmessage.Part
	var walk func(p *moxmessage.Part, root bool)
	walk = func(p *moxmessage.Part, root bool) {
		if !root && isExplicitAttachment(p) {
			return
		}
		if len(p.Parts) > 0 {
			for i := range p.Parts {
				walk(&p.Parts[i], false)
			}
			return
		}
		if !strings.EqualFold(p.MediaType, "TEXT") && p.MediaType != "" {
			return
		}
		if strings.EqualFold(p.MediaSubType, "HTML") {
			htmlParts = append(htmlParts, p)
		} else if text == "" {
			b, _ := io.ReadAll(p.Reader())
			text = string(b)
		}
	}
	walk(&part, true)
	if len(htmlParts) > 1 {
		return text, "", cc, true
	}
	if len(htmlParts) == 1 {
		b, _ := io.ReadAll(io.LimitReader(htmlParts[0].Reader(), maxRenderableHTMLBytes+1))
		if len(b) > maxRenderableHTMLBytes {
			return text, "", cc, true
		}
		html = string(b)
	}
	return text, html, cc, false
}

func isExplicitAttachment(part *moxmessage.Part) bool {
	if part.ContentDisposition == nil {
		return false
	}
	disposition, _, _ := part.DispositionFilename()
	if strings.EqualFold(disposition, "attachment") {
		return true
	}
	raw := strings.TrimSpace(*part.ContentDisposition)
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}
	return strings.EqualFold(strings.Trim(strings.TrimSpace(raw), `"`), "attachment")
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
	primary := env.replyTo
	if primary == "" {
		primary = env.from
	}
	if primary != "" {
		to = append(to, primary)
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
