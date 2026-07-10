package webapi

import (
	"context"
	"io"
	"net/http"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// GET /webapi/v0/drafts
func (s *Server) listDrafts(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var out []messageSummary
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		mb, e := a.acc.MailboxFind(tx, "Drafts")
		if e != nil {
			return e
		}
		if mb == nil {
			return nil // no Drafts mailbox yet → empty list
		}
		msgs, e := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
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
	return http.StatusOK, map[string]any{"drafts": out}, nil
}

// POST /webapi/v0/drafts — compose and store a draft (no send).
func (s *Server) createDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var req sendRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	m := &store.Message{}
	m.Flags.Draft = true
	if _, err := a.acc.DeliverMailbox("Drafts", m, memBlob(raw)); err != nil {
		return 0, nil, internalErr("draft_failed", err)
	}
	return http.StatusCreated, map[string]any{"id": emailID(*m)}, nil
}

// POST /webapi/v0/drafts/{id}/send — submit an existing draft.
func (s *Server) sendDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Submission == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	id := r.PathValue("id")
	var (
		raw    []byte
		rcpts  []string
		mailFr = a.login
	)
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		msgs, e := loadGroup(tx, a.acc, id)
		if e != nil {
			return e
		}
		br := a.acc.MessageReader(msgs[0])
		raw, _ = io.ReadAll(br)
		br.Close()
		env := parseEnvelope(raw)
		rcpts = allRecipients(env.to, env.cc, nil)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if len(rcpts) == 0 {
		return 0, nil, errStatus(http.StatusUnprocessableEntity, "no_recipients", "draft has no recipients")
	}
	ids, err := s.Submission.Submit(ctx, a.scope.Tenant().ID, a.acc.ID(), mailFr, rcpts, raw)
	if err != nil {
		return 0, nil, internalErr("submit_failed", err)
	}
	return http.StatusAccepted, map[string]any{"submissionIds": ids}, nil
}

// DELETE /webapi/v0/drafts/{id}
func (s *Server) deleteDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	return s.deleteMessage(ctx, a, r)
}
