// Package webapi is octo-mail's RESTful HTTP/JSON API for programmatic mail. It
// is a per-account surface — authenticated with an account API key
// (Authorization: Bearer omk_...) or HTTP Basic — for sending mail and managing
// messages, threads, drafts, mailboxes, and the suppression list, without
// speaking SMTP/IMAP/JMAP. It sits on the same kernel primitives: Send enqueues
// to the shared outbound queue; message ops go through the account's change-log.
//
// The API is resource-oriented under /webapi/v0: real HTTP verbs, correct status
// codes, camelCase JSON, and a small {"error":{"code","message"}} body on
// failure. Provisioning (tenants/accounts/domains) is deliberately NOT here — it
// lives on the admin surface; an account key can only reach its own mailbox.
package webapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/mjl-/mox/smtp"
)

// Server serves the REST webapi. Submission enqueues outbound mail; Suppressions
// manages the per-account suppression list.
type Server struct {
	Dir          directory.Directory
	Submission   *submit.Submitter
	Suppressions *deliverability.Suppressions
}

// Handler mounts the REST routes under /webapi/v0 using method+path patterns
// (Go 1.22 ServeMux). Every route is authenticated in the handler via s.auth.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Messages.
	mux.HandleFunc("GET /webapi/v0/messages", s.h(s.listMessages))
	mux.HandleFunc("POST /webapi/v0/messages", s.h(s.sendMessage))
	mux.HandleFunc("GET /webapi/v0/messages/{id}", s.h(s.getMessage))
	mux.HandleFunc("PATCH /webapi/v0/messages/{id}", s.h(s.patchMessage))
	mux.HandleFunc("DELETE /webapi/v0/messages/{id}", s.h(s.deleteMessage))
	mux.HandleFunc("GET /webapi/v0/messages/{id}/raw", s.hRaw(s.rawMessage))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/reply", s.h(s.replyMessage))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/reply-all", s.h(s.replyAllMessage))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/forward", s.h(s.forwardMessage))
	// Threads.
	mux.HandleFunc("GET /webapi/v0/threads/{id}", s.h(s.getThread))
	// Drafts.
	mux.HandleFunc("GET /webapi/v0/drafts", s.h(s.listDrafts))
	mux.HandleFunc("POST /webapi/v0/drafts", s.h(s.createDraft))
	mux.HandleFunc("POST /webapi/v0/drafts/{id}/send", s.h(s.sendDraft))
	mux.HandleFunc("DELETE /webapi/v0/drafts/{id}", s.h(s.deleteDraft))
	// Mailboxes.
	mux.HandleFunc("GET /webapi/v0/mailboxes", s.h(s.listMailboxes))
	// Suppressions.
	mux.HandleFunc("GET /webapi/v0/suppressions", s.h(s.listSuppressions))
	mux.HandleFunc("GET /webapi/v0/suppressions/{address}", s.h(s.getSuppression))
	mux.HandleFunc("PUT /webapi/v0/suppressions/{address}", s.h(s.putSuppression))
	mux.HandleFunc("DELETE /webapi/v0/suppressions/{address}", s.h(s.deleteSuppression))
	return mux
}

// authCtx carries the authenticated account for a request.
type authCtx struct {
	acc   store.Account
	scope directory.TenantScope
	login string
}

func (s *Server) auth(r *http.Request) (authCtx, error) {
	// API key first: Authorization: Bearer omk_<prefix>_<secret>.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omk_") {
		token := strings.TrimPrefix(h, "Bearer ")
		scope, princ, _, err := s.Dir.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		addr, err := smtp.ParseAddress(princ.Login)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "bad login address")
		}
		acc, err := scope.AccountForAddress(r.Context(), addr.Path())
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "no account for login")
		}
		return authCtx{acc: acc, scope: scope, login: princ.Login}, nil
	}

	login, password, ok := r.BasicAuth()
	if !ok {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "missing credentials")
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "bad login address")
	}
	scope, _, err := s.Dir.AuthenticatePrincipal(r.Context(), login, directory.PasswordCredential(password))
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
	}
	acc, err := scope.AccountForAddress(r.Context(), addr.Path())
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "no account for login")
	}
	return authCtx{acc: acc, scope: scope, login: login}, nil
}

// handler is a REST handler that returns (status, body) or an error. A nil body
// with status 204 writes no content.
type handler func(ctx context.Context, a authCtx, r *http.Request) (status int, body any, err error)

// h wraps a handler with auth + JSON error mapping.
func (s *Server) h(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.auth(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		status, body, err := fn(r.Context(), a, r)
		if err != nil {
			writeErr(w, err)
			return
		}
		if status == http.StatusNoContent || body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	}
}

// hRaw wraps a handler that streams raw bytes (message/rfc822).
func (s *Server) hRaw(fn func(ctx context.Context, a authCtx, r *http.Request) (store.BlobReader, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.auth(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		rc, err := fn(r.Context(), a, r)
		if err != nil {
			writeErr(w, err)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "message/rfc822")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 32*1024)
		for {
			n, e := rc.Read(buf)
			if n > 0 {
				if _, we := w.Write(buf[:n]); we != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}
}

// --- shared helpers ---

// decode reads and JSON-decodes the request body (capped) into v.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<20))
	if err := dec.Decode(v); err != nil {
		return errStatus(http.StatusBadRequest, "invalid_body", "invalid JSON body: "+err.Error())
	}
	return nil
}

// parseEmailID decodes an "E<n>" message id to its effective email id.
func parseEmailID(id string) (int64, bool) {
	if len(id) < 2 || id[0] != 'E' {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil
}

func emailID(m store.Message) string {
	return "E" + strconv.FormatInt(m.EffectiveEmailID(), 10)
}

// loadGroup loads all live rows of a message (across mailboxes) by its "E<n>" id.
func loadGroup(tx store.Tx, acc store.Account, id string) ([]store.Message, error) {
	gid, ok := parseEmailID(id)
	if !ok {
		return nil, errStatus(http.StatusBadRequest, "invalid_id", "invalid message id")
	}
	msgs, err := acc.MessagesByEmailID(tx, gid)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errStatus(http.StatusNotFound, "not_found", "no such message")
	}
	return msgs, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusError carries an HTTP status + machine code + message.
type statusError struct {
	status int
	code   string
	msg    string
}

func (e *statusError) Error() string { return e.msg }

func errStatus(status int, code, msg string) *statusError {
	return &statusError{status: status, code: code, msg: msg}
}

// writeErr renders an error: a *statusError uses its status; anything else is 500.
func writeErr(w http.ResponseWriter, err error) {
	se, ok := err.(*statusError)
	if !ok {
		se = errStatus(http.StatusInternalServerError, "internal", err.Error())
	}
	writeJSON(w, se.status, map[string]any{
		"error": map[string]string{"code": se.code, "message": se.msg},
	})
}

// senderDomain returns the account login's domain, for Message-ID generation.
func (a authCtx) senderDomain() string {
	if i := strings.LastIndex(a.login, "@"); i >= 0 {
		return a.login[i+1:]
	}
	return "localhost"
}
