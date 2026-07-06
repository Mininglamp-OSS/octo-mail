// Package jmapd is a compact, real JMAP server (RFC 8620 core + RFC 8621 mail
// subset) bound to the octo-mail kernel. Its purpose is to demonstrate the
// architecture's central symmetry: IMAP and JMAP are two projections of the same
// per-account change-log. Concretely, the JMAP "state" string IS the account's
// changelog offset, and Email/changes(sinceState=n) is the same replay
// (modseq > n) that IMAP serves as CONDSTORE CHANGEDSINCE n — two renderers over
// one log.
//
// It speaks HTTP/JSON and is tested with the standard net/http client.
package jmapd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/smtp"
)

// Server serves JMAP over HTTP, resolving the authenticated principal through
// the directory (structural tenant isolation).
type Server struct {
	Dir     directory.Directory
	BaseURL string // e.g. "http://localhost:8080"
	// Submission, if set, enables EmailSubmission/set: it enqueues outbound mail
	// to the shared queue (the JMAP counterpart of SMTP submission on 587).
	Submission *submit.Submitter
	// Blob, if set, enables the upload endpoint and Email/set create: uploaded
	// message bytes are stored here (content-addressed, per tenant) and referenced
	// by blobId.
	Blob blob.Store
}

// Handler returns an http.Handler serving /jmap/session and /jmap/api.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/jmap/session", s.handleSession)
	mux.HandleFunc("/jmap/api", s.handleAPI)
	mux.HandleFunc("/jmap/download/", s.handleDownload)
	mux.HandleFunc("/jmap/upload/", s.handleUpload)
	mux.HandleFunc("/jmap/eventsource", s.handleEventSource)
	return mux
}

// handleUpload implements the JMAP upload endpoint (RFC 8620 §6.1): POST raw
// bytes, stored content-addressed in the tenant's blob store, returning a
// blobId ("U<tenantID>-<hash>") the client can reference in Email/set create.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	acc, scope, _, err := s.authAccount(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.Blob == nil {
		http.Error(w, "upload not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := scope.Tenant().ID
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	ref, size, err := s.Blob.Put(r.Context(), tenantID, bytes.NewReader(data))
	if err != nil {
		http.Error(w, "store blob", http.StatusInternalServerError)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"blobId":    "U" + strconv.FormatInt(tenantID, 10) + "-" + string(ref),
		"type":      ct,
		"size":      size,
	})
}

// handleEventSource implements the JMAP push channel (RFC 8620 §7.3) as
// Server-Sent Events: it registers a Comm on the account's change stream and
// emits a "state" event whenever the account's changelog advances, so clients
// can re-sync. Closes when the client disconnects.
func (s *Server) handleEventSource(w http.ResponseWriter, r *http.Request) {
	acc, _, _, err := s.authAccount(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	comm := acc.RegisterComm()
	defer comm.Close()

	accID := strconv.FormatInt(acc.ID(), 10)
	// Initial state event so a fresh subscriber knows the current offset.
	if st, e := accountState(r.Context(), acc); e == nil {
		fmt.Fprintf(w, "event: state\ndata: {\"@type\":\"StateChange\",\"changed\":{\"%s\":{\"Email\":\"%s\"}}}\n\n", accID, st)
		flusher.Flush()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case _, ok := <-comm.Changes:
			if !ok {
				return
			}
			st, e := accountState(r.Context(), acc)
			if e != nil {
				continue
			}
			fmt.Fprintf(w, "event: state\ndata: {\"@type\":\"StateChange\",\"changed\":{\"%s\":{\"Email\":\"%s\"}}}\n\n", accID, st)
			flusher.Flush()
		}
	}
}

// handleDownload serves raw message bytes for a blobId (RFC 8620 §6.2). The
// blobId here is the Email id ("E<emailID>"); the account is verified via Basic
// auth. Path: /jmap/download/{accountId}/{blobId}/{name}.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	acc, _, _, err := s.authAccount(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Parse /jmap/download/<accountId>/<blobId>/<name>.
	rest := strings.TrimPrefix(r.URL.Path, "/jmap/download/")
	segs := strings.SplitN(rest, "/", 3)
	if len(segs) < 2 {
		http.Error(w, "bad download path", http.StatusBadRequest)
		return
	}
	blobID := segs[1]
	var data []byte
	err = acc.Tx(r.Context(), func(tx store.Tx) error {
		group, ok := s.emailGroup(tx, acc, blobID)
		if !ok {
			return errNotFoundJMAP
		}
		br := acc.MessageReader(group[0])
		defer br.Close()
		var e error
		data, e = io.ReadAll(br)
		return e
	})
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// authAccount extracts the account from the request's credentials via the
// directory. It accepts either an API key (Authorization: Bearer omk_...) or
// HTTP Basic auth (login + password). Both resolve to the same
// (account, scope, login) tuple, so every endpoint handles them uniformly.
func (s *Server) authAccount(r *http.Request) (store.Account, directory.TenantScope, string, error) {
	// API key first: Authorization: Bearer omk_<prefix>_<secret>.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omk_") {
		token := strings.TrimPrefix(h, "Bearer ")
		scope, princ, _, err := s.Dir.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return nil, nil, "", err
		}
		addr, err := smtp.ParseAddress(princ.Login)
		if err != nil {
			return nil, nil, "", err
		}
		acc, err := scope.AccountForAddress(r.Context(), addr.Path())
		if err != nil {
			return nil, nil, "", err
		}
		return acc, scope, princ.Login, nil
	}

	login, password, ok := r.BasicAuth()
	if !ok {
		return nil, nil, "", fmt.Errorf("missing credentials")
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return nil, nil, "", err
	}
	scope, _, err := s.Dir.AuthenticatePrincipal(r.Context(), login, directory.PasswordCredential(password))
	if err != nil {
		return nil, nil, "", err
	}
	acc, err := scope.AccountForAddress(r.Context(), addr.Path())
	if err != nil {
		return nil, nil, "", err
	}
	return acc, scope, login, nil
}

// accountState returns the account's current changelog head as a JMAP state
// string. It reads the head directly (not via a mutating Tx), so querying state
// never advances it.
func accountState(ctx context.Context, acc store.Account) (string, error) {
	head, err := acc.ChangelogHead(ctx)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(int64(head), 10), nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	acc, scope, login, err := s.authAccount(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accID := strconv.FormatInt(acc.ID(), 10)
	session := map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":     50_000_000,
				"maxCallsInRequest": 64,
				"maxObjectsInGet":   1000,
				"maxObjectsInSet":   1000,
			},
			"urn:ietf:params:jmap:mail":             map[string]any{},
			"urn:ietf:params:jmap:vacationresponse": map[string]any{},
		},
		"accounts": map[string]any{
			accID: map[string]any{
				"name":       login,
				"isPersonal": true,
				"isReadOnly": false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":             map[string]any{},
					"urn:ietf:params:jmap:vacationresponse": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]any{
			"urn:ietf:params:jmap:mail": accID,
		},
		"username":       login,
		"apiUrl":         s.BaseURL + "/jmap/api",
		"downloadUrl":    s.BaseURL + "/jmap/download/{accountId}/{blobId}/{name}",
		"uploadUrl":      s.BaseURL + "/jmap/upload/{accountId}/",
		"eventSourceUrl": s.BaseURL + "/jmap/eventsource",
		"state":          "0",
	}
	_ = scope
	writeJSON(w, http.StatusOK, session)
}

// Request is a JMAP API request (RFC 8620 §3.3).
type Request struct {
	Using       []string             `json:"using"`
	MethodCalls [][3]json.RawMessage `json:"methodCalls"`
}

// invocation is one [name, args, callId] triple, decoded.
type invocation struct {
	name   string
	args   map[string]json.RawMessage
	callID string
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	acc, scope, login, err := s.authAccount(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var responses [][3]any
	for _, mc := range req.MethodCalls {
		var name, callID string
		_ = json.Unmarshal(mc[0], &name)
		_ = json.Unmarshal(mc[2], &callID)
		var args map[string]json.RawMessage
		_ = json.Unmarshal(mc[1], &args)
		inv := invocation{name: name, args: args, callID: callID}

		resName, resArgs := s.dispatch(r.Context(), acc, scope, login, inv)
		responses = append(responses, [3]any{resName, resArgs, callID})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"methodResponses": responses,
	})
}

// dispatch runs one JMAP method call, returning the response name and args.
func (s *Server) dispatch(ctx context.Context, acc store.Account, scope directory.TenantScope, login string, inv invocation) (string, any) {
	switch inv.name {
	case "Mailbox/get":
		return s.mailboxGet(ctx, acc, inv)
	case "Email/query":
		return s.emailQuery(ctx, acc, inv)
	case "Email/get":
		return s.emailGet(ctx, acc, inv)
	case "Email/changes":
		return s.emailChanges(ctx, acc, inv)
	case "Email/set":
		return s.emailSet(ctx, acc, inv)
	case "Thread/get":
		return s.threadGet(ctx, acc, inv)
	case "Mailbox/set":
		return s.mailboxSet(ctx, acc, inv)
	case "Email/copy":
		return s.emailCopy(ctx, acc, inv)
	case "Identity/get":
		return s.identityGet(ctx, acc, login, inv)
	case "SearchSnippet/get":
		return s.searchSnippetGet(ctx, acc, inv)
	case "VacationResponse/get":
		return s.vacationGet(ctx, acc, inv)
	case "VacationResponse/set":
		return s.vacationSet(ctx, acc, inv)
	case "EmailSubmission/set":
		return s.emailSubmissionSet(ctx, acc, scope, login, inv)
	default:
		return "error", map[string]any{"type": "unknownMethod"}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
