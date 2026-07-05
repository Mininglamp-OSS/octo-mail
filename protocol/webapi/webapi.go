// Package webapi is octo-mail's HTTP/JSON RPC for programmatic mail, matching the
// shape of the webapi (a reference webapi): a per-account-authenticated surface for
// sending mail and managing messages/suppressions without speaking SMTP/IMAP.
// Each method is POST /webapi/v0/<Method> with a JSON request body and JSON
// response, authenticated with the account's own credentials (HTTP Basic) — not
// the admin token. It sits on the same kernel primitives as SMTP/IMAP/JMAP: Send
// enqueues to the one shared outbound queue; message ops go through the account's
// change-log.
package webapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/mjl-/mox/smtp"
)

// Server serves the webapi. Submission enqueues outbound mail; Suppressions
// manages the per-account suppression list.
type Server struct {
	Dir          directory.Directory
	Submission   *submit.Submitter
	Suppressions *deliverability.Suppressions
}

// Handler returns the HTTP handler mounting all webapi methods under /webapi/v0/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/webapi/v0/Send", s.method(s.send))
	mux.HandleFunc("/webapi/v0/SuppressionList", s.method(s.suppressionList))
	mux.HandleFunc("/webapi/v0/SuppressionAdd", s.method(s.suppressionAdd))
	mux.HandleFunc("/webapi/v0/SuppressionRemove", s.method(s.suppressionRemove))
	mux.HandleFunc("/webapi/v0/SuppressionPresent", s.method(s.suppressionPresent))
	mux.HandleFunc("/webapi/v0/MessageGet", s.method(s.messageGet))
	mux.HandleFunc("/webapi/v0/MessageRawGet", s.methodRaw(s.messageRawGet))
	mux.HandleFunc("/webapi/v0/MessageDelete", s.method(s.messageDelete))
	mux.HandleFunc("/webapi/v0/MessageFlagsAdd", s.method(s.messageFlagsAdd))
	mux.HandleFunc("/webapi/v0/MessageFlagsRemove", s.method(s.messageFlagsRemove))
	return mux
}

// authCtx carries the authenticated account for a request.
type authCtx struct {
	acc   store.Account
	scope directory.TenantScope
	login string
}

func (s *Server) auth(r *http.Request) (authCtx, error) {
	login, password, ok := r.BasicAuth()
	if !ok {
		return authCtx{}, errUser("missing basic auth")
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return authCtx{}, errUser("bad login address")
	}
	scope, _, err := s.Dir.AuthenticatePrincipal(r.Context(), login, directory.PasswordCredential(password))
	if err != nil {
		return authCtx{}, errUser("authentication failed")
	}
	acc, err := scope.AccountForAddress(r.Context(), addr.Path())
	if err != nil {
		return authCtx{}, errUser("no account for login")
	}
	return authCtx{acc: acc, scope: scope, login: login}, nil
}

// method wraps a JSON-in/JSON-out handler with auth + error mapping.
func (s *Server) method(fn func(ctx context.Context, a authCtx, body []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "protocol", "POST required")
			return
		}
		a, err := s.auth(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "user", err.Error())
			return
		}
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<20))
		res, err := fn(r.Context(), a, body)
		if err != nil {
			if ue, ok := err.(apiError); ok {
				writeErr(w, http.StatusOK, ue.code, ue.msg)
				return
			}
			writeErr(w, http.StatusOK, "server", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// methodRaw wraps a handler returning raw bytes (e.g. MessageRawGet).
func (s *Server) methodRaw(fn func(ctx context.Context, a authCtx, body []byte) (io.ReadCloser, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "protocol", "POST required")
			return
		}
		a, err := s.auth(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "user", err.Error())
			return
		}
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		rc, err := fn(r.Context(), a, body)
		if err != nil {
			writeErr(w, http.StatusOK, "user", err.Error())
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "message/rfc822")
		_, _ = io.Copy(w, rc)
	}
}

// --- Send ---

type NameAddress struct {
	Name    string `json:"Name,omitempty"`
	Address string `json:"Address"`
}

type SendRequest struct {
	From      NameAddress   `json:"From"`
	To        []NameAddress `json:"To"`
	Subject   string        `json:"Subject"`
	Text      string        `json:"Text"`
	MessageID string        `json:"MessageID,omitempty"`
}

type SendResult struct {
	MessageID  string  `json:"MessageID"`
	Submission []int64 `json:"Submission"`
}

func (s *Server) send(ctx context.Context, a authCtx, body []byte) (any, error) {
	if s.Submission == nil {
		return nil, errServer("submission not enabled")
	}
	var req SendRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errUser("bad request json")
	}
	from := req.From.Address
	if from == "" {
		from = a.login
	}
	if len(req.To) == 0 {
		return nil, errUser("at least one To addressee required")
	}
	var rcpts []string
	var toHdr []string
	for _, t := range req.To {
		if t.Address == "" {
			continue
		}
		rcpts = append(rcpts, t.Address)
		toHdr = append(toHdr, t.Address)
	}
	if len(rcpts) == 0 {
		return nil, errUser("no valid recipients")
	}
	msgID := req.MessageID
	if msgID == "" {
		msgID = "<" + strconv.FormatInt(a.acc.ID(), 10) + "." + strings.ReplaceAll(from, "@", ".") + ".webapi@octo-mail>"
	}
	// Compose a minimal RFC822 message.
	var b strings.Builder
	b.WriteString("Message-ID: " + msgID + "\r\n")
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(toHdr, ", ") + "\r\n")
	b.WriteString("Subject: " + req.Subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(req.Text)
	if !strings.HasSuffix(req.Text, "\n") {
		b.WriteString("\r\n")
	}

	ids, err := s.Submission.Submit(ctx, a.scope.Tenant().ID, a.acc.ID(), from, rcpts, []byte(b.String()))
	if err != nil {
		return nil, errServer(err.Error())
	}
	return SendResult{MessageID: msgID, Submission: ids}, nil
}

// --- Suppression* ---

type SuppressionListResult struct {
	Suppressions []string `json:"Suppressions"`
}

func (s *Server) suppressionList(ctx context.Context, a authCtx, body []byte) (any, error) {
	if s.Suppressions == nil {
		return nil, errServer("suppressions not enabled")
	}
	list, err := s.Suppressions.List(ctx, a.acc.ID())
	if err != nil {
		return nil, errServer(err.Error())
	}
	if list == nil {
		list = []string{}
	}
	return SuppressionListResult{Suppressions: list}, nil
}

type SuppressionAddRequest struct {
	Address string `json:"Address"`
	Reason  string `json:"Reason,omitempty"`
}

func (s *Server) suppressionAdd(ctx context.Context, a authCtx, body []byte) (any, error) {
	if s.Suppressions == nil {
		return nil, errServer("suppressions not enabled")
	}
	var req SuppressionAddRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Address == "" {
		return nil, errUser("Address required")
	}
	if err := s.Suppressions.Add(ctx, a.scope.Tenant().ID, a.acc.ID(), req.Address, req.Reason); err != nil {
		return nil, errServer(err.Error())
	}
	return map[string]any{"Added": true}, nil
}

type SuppressionRemoveRequest struct {
	Address string `json:"Address"`
}

func (s *Server) suppressionRemove(ctx context.Context, a authCtx, body []byte) (any, error) {
	if s.Suppressions == nil {
		return nil, errServer("suppressions not enabled")
	}
	var req SuppressionRemoveRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Address == "" {
		return nil, errUser("Address required")
	}
	if err := s.Suppressions.Remove(ctx, a.acc.ID(), req.Address); err != nil {
		return nil, errServer(err.Error())
	}
	return map[string]any{"Removed": true}, nil
}

type SuppressionPresentRequest struct {
	Address string `json:"Address"`
}

func (s *Server) suppressionPresent(ctx context.Context, a authCtx, body []byte) (any, error) {
	if s.Suppressions == nil {
		return nil, errServer("suppressions not enabled")
	}
	var req SuppressionPresentRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Address == "" {
		return nil, errUser("Address required")
	}
	present, err := s.Suppressions.Suppressed(ctx, a.acc.ID(), req.Address)
	if err != nil {
		return nil, errServer(err.Error())
	}
	return map[string]any{"Present": present}, nil
}

// --- Message* ---

// msgRef is the message identifier used by webapi: a mailbox name + UID.
type msgRef struct {
	Mailbox string `json:"Mailbox"`
	UID     int64  `json:"UID"`
}

func (s *Server) resolve(ctx context.Context, a authCtx, ref msgRef) (store.Mailbox, store.Message, error) {
	var mb store.Mailbox
	var m store.Message
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		found, e := a.acc.MailboxFind(tx, ref.Mailbox)
		if e != nil {
			return e
		}
		if found == nil {
			return errUser("no such mailbox")
		}
		mb = *found
		msgs, e := tx.QueryMessage().FilterMailbox(mb.ID).FilterUIDRange(store.UID(ref.UID), store.UID(ref.UID)).List()
		if e != nil {
			return e
		}
		if len(msgs) == 0 {
			return errUser("no such message")
		}
		m = msgs[0]
		return nil
	})
	return mb, m, err
}

type MessageGetResult struct {
	UID     int64    `json:"UID"`
	Mailbox string   `json:"Mailbox"`
	Size    int64    `json:"Size"`
	Flags   []string `json:"Flags"`
}

func (s *Server) messageGet(ctx context.Context, a authCtx, body []byte) (any, error) {
	var ref msgRef
	if err := json.Unmarshal(body, &ref); err != nil {
		return nil, errUser("bad request json")
	}
	mb, m, err := s.resolve(ctx, a, ref)
	if err != nil {
		return nil, err
	}
	return MessageGetResult{UID: int64(m.UID), Mailbox: mb.Name, Size: m.Size, Flags: flagList(m)}, nil
}

func (s *Server) messageRawGet(ctx context.Context, a authCtx, body []byte) (io.ReadCloser, error) {
	var ref msgRef
	if err := json.Unmarshal(body, &ref); err != nil {
		return nil, errUser("bad request json")
	}
	_, m, err := s.resolve(ctx, a, ref)
	if err != nil {
		return nil, err
	}
	return a.acc.MessageReader(m), nil
}

func (s *Server) messageDelete(ctx context.Context, a authCtx, body []byte) (any, error) {
	var ref msgRef
	if err := json.Unmarshal(body, &ref); err != nil {
		return nil, errUser("bad request json")
	}
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		found, e := a.acc.MailboxFind(tx, ref.Mailbox)
		if e != nil {
			return e
		}
		if found == nil {
			return errUser("no such mailbox")
		}
		msgs, e := tx.QueryMessage().FilterMailbox(found.ID).FilterUIDRange(store.UID(ref.UID), store.UID(ref.UID)).List()
		if e != nil {
			return e
		}
		if len(msgs) == 0 {
			return errUser("no such message")
		}
		_, _, e = a.acc.MessageRemove(tx, 0, found, store.RemoveOpts{Expunge: true}, msgs[0])
		return e
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"Deleted": true}, nil
}

type MessageFlagsRequest struct {
	Mailbox string   `json:"Mailbox"`
	UID     int64    `json:"UID"`
	Flags   []string `json:"Flags"`
}

func (s *Server) messageFlagsAdd(ctx context.Context, a authCtx, body []byte) (any, error) {
	return s.messageFlags(ctx, a, body, true)
}

func (s *Server) messageFlagsRemove(ctx context.Context, a authCtx, body []byte) (any, error) {
	return s.messageFlags(ctx, a, body, false)
}

func (s *Server) messageFlags(ctx context.Context, a authCtx, body []byte, add bool) (any, error) {
	var req MessageFlagsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errUser("bad request json")
	}
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		found, e := a.acc.MailboxFind(tx, req.Mailbox)
		if e != nil {
			return e
		}
		if found == nil {
			return errUser("no such mailbox")
		}
		msgs, e := tx.QueryMessage().FilterMailbox(found.ID).FilterUIDRange(store.UID(req.UID), store.UID(req.UID)).List()
		if e != nil {
			return e
		}
		if len(msgs) == 0 {
			return errUser("no such message")
		}
		m := msgs[0]
		for _, f := range req.Flags {
			setFlag(&m, f, add)
		}
		return tx.Update(&m)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"OK": true}, nil
}

// --- helpers ---

func flagList(m store.Message) []string {
	var f []string
	if m.Seen {
		f = append(f, `\Seen`)
	}
	if m.Answered {
		f = append(f, `\Answered`)
	}
	if m.Flagged {
		f = append(f, `\Flagged`)
	}
	if m.Draft {
		f = append(f, `\Draft`)
	}
	if m.Deleted {
		f = append(f, `\Deleted`)
	}
	if m.Junk {
		f = append(f, `$Junk`)
	}
	f = append(f, m.Keywords...)
	if f == nil {
		f = []string{}
	}
	return f
}

func setFlag(m *store.Message, name string, v bool) {
	switch strings.ToLower(name) {
	case `\seen`:
		m.Seen = v
	case `\answered`:
		m.Answered = v
	case `\flagged`:
		m.Flagged = v
	case `\draft`:
		m.Draft = v
	case `\deleted`:
		m.Deleted = v
	case `$junk`, `\junk`:
		m.Junk = v
	case `$notjunk`, `\notjunk`:
		m.Notjunk = v
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"Error": map[string]string{"Code": code, "Message": msg}})
}

// apiError carries a webapi error code + message.
type apiError struct {
	code string
	msg  string
}

func (e apiError) Error() string { return e.msg }

func errUser(msg string) apiError   { return apiError{code: "user", msg: msg} }
func errServer(msg string) apiError { return apiError{code: "server", msg: msg} }
