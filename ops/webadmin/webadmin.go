// Package webadmin is octo-mail's HTTP admin/account API: the product-layer surface
// for operators, exposed as a JSON API over the kernel. It covers
// provisioning (create tenant/domain/account/address, set password, generate
// DKIM) and observability (quota usage, reputation status, suppression list).
// Auth is a static admin bearer token; per-account self-service endpoints verify
// the account's own credential via the directory.
package webadmin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/ops/obs"
)

// Server serves the admin/account API.
type Server struct {
	Pool *pgxpool.Pool
	Dir  interface {
		SetPassword(ctx context.Context, login, password string) error
	}
	Reputation *deliverability.Service
	AdminToken string // required bearer token for /admin/* endpoints
	// Log, if set, records the full internal error for a 500 response; clients only
	// ever receive a generic message (no raw DB/driver text — constraint names,
	// SQL, paths). Optional.
	Log *slog.Logger

	// QueueFailDSN, if set, generates a permanent-failure bounce DSN when an
	// operator fails a queued message via /admin/queue/fail. When nil, fail drops
	// the message without a DSN (same as /admin/queue/drop).
	QueueFailDSN func(ctx context.Context, m queue.Msg) error
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/tenants", s.requireAdmin(s.handleCreateTenant))              // POST {name}
	mux.HandleFunc("/admin/accounts", s.requireAdmin(s.handleCreateAccount))            // POST {tenant_id,name}
	mux.HandleFunc("/admin/addresses", s.requireAdmin(s.handleCreateAddress))           // POST {tenant_id,domain,localpart,account}
	mux.HandleFunc("/admin/domains", s.requireAdmin(s.handleCreateDomain))              // POST {tenant_id,domain}
	mux.HandleFunc("/admin/password", s.requireAdmin(s.handleSetPassword))              // POST {login,password}
	mux.HandleFunc("/admin/quota", s.requireAdmin(s.handleQuota))                       // GET ?account_id=
	mux.HandleFunc("/admin/reputation", s.requireAdmin(s.handleReputation))             // GET ?tenant_id=&domain=
	mux.HandleFunc("/admin/queue", s.requireAdmin(s.handleQueueList))                   // GET ?tenant_id=&account_id=
	mux.HandleFunc("/admin/queue/kick", s.requireAdmin(s.handleQueueKick))              // POST {ids|tenant_id|account_id}
	mux.HandleFunc("/admin/queue/schedule", s.requireAdmin(s.handleQueueSchedule))      // POST {delay, ids|tenant_id|account_id}
	mux.HandleFunc("/admin/queue/schedule-at", s.requireAdmin(s.handleQueueScheduleAt)) // POST {at, filter}
	mux.HandleFunc("/admin/queue/requiretls", s.requireAdmin(s.handleQueueRequireTLS))  // POST {mode, filter}
	mux.HandleFunc("/admin/queue/hold", s.requireAdmin(s.handleQueueHold))              // POST {hold, ids|tenant_id|account_id}
	mux.HandleFunc("/admin/queue/drop", s.requireAdmin(s.handleQueueDrop))              // POST {ids|tenant_id|account_id}
	mux.HandleFunc("/admin/queue/fail", s.requireAdmin(s.handleQueueFail))              // POST {ids|tenant_id|account_id}
	mux.HandleFunc("/admin/queue/retired", s.requireAdmin(s.handleQueueRetired))        // GET ?tenant_id=&account_id=
	mux.HandleFunc("/admin/queue/results", s.requireAdmin(s.handleQueueResults))        // GET ?id=
	mux.HandleFunc("/admin/queue/holdrules", s.requireAdmin(s.handleHoldRules))         // GET ?tenant_id= | POST {tenant_id,...} | DELETE ?id=
	mux.HandleFunc("/healthz", s.handleHealth)                                          // GET (no auth)
	mux.Handle("/metrics", s.requireAdmin(obs.Handler().ServeHTTP))                     // Prometheus metrics (admin-gated)
	return mux
}

// tokenValid reports whether the request carries the configured admin bearer
// token, compared in constant time so the comparison can't be used as a timing
// oracle to recover the token byte by byte. An unset AdminToken never validates.
func (s *Server) tokenValid(r *http.Request) bool {
	if s.AdminToken == "" {
		return false
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.AdminToken)) == 1
}

func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenValid(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.Pool.Ping(r.Context()); err != nil {
		if s.Log != nil {
			s.Log.WarnContext(r.Context(), "webadmin health check failed", "err", err)
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "down"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	var id int64
	if err := s.Pool.QueryRow(r.Context(), `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, req.Name).Scan(&id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID int64  `json:"tenant_id"`
		Name     string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	var id int64
	if err := s.Pool.QueryRow(r.Context(),
		`INSERT INTO accounts (tenant_id, name) VALUES ($1,$2) RETURNING id`, req.TenantID, req.Name).Scan(&id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID int64  `json:"tenant_id"`
		Domain   string `json:"domain"`
	}
	if !decode(w, r, &req) {
		return
	}
	var id int64
	if err := s.Pool.QueryRow(r.Context(),
		`INSERT INTO domains (tenant_id, domain) VALUES ($1,$2) RETURNING id`, req.TenantID, req.Domain).Scan(&id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleCreateAddress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID  int64  `json:"tenant_id"`
		Domain    string `json:"domain"`
		Localpart string `json:"localpart"`
		Account   string `json:"account"`
	}
	if !decode(w, r, &req) {
		return
	}
	// Validate before touching the DB: a blank localpart/domain would create an
	// unusable address (and an empty "@domain" principal login).
	if req.TenantID == 0 || req.Domain == "" || req.Localpart == "" || req.Account == "" {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "tenant_id, domain, localpart, and account are required"))
		return
	}
	var domID, accID int64
	if err := s.Pool.QueryRow(r.Context(), `SELECT id FROM domains WHERE tenant_id=$1 AND domain=$2`, req.TenantID, req.Domain).Scan(&domID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.Pool.QueryRow(r.Context(), `SELECT id FROM accounts WHERE tenant_id=$1 AND name=$2`, req.TenantID, req.Account).Scan(&accID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	// The address row and its authenticating principal must be created atomically:
	// a half-succeeded provisioning (address with no login principal) leaves an
	// account that can't authenticate at that address, reported as success.
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // rolled back unless Commit succeeds
	var id int64
	if err := tx.QueryRow(r.Context(),
		`INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,$4) RETURNING id`,
		req.TenantID, domID, accID, req.Localpart).Scan(&id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	// A principal login for the address (so the account can authenticate). ON
	// CONFLICT DO NOTHING tolerates a pre-existing login, but a genuine error must
	// roll back the address insert rather than be discarded.
	if _, err := tx.Exec(r.Context(), `INSERT INTO principals (tenant_id, login) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		req.TenantID, req.Localpart+"@"+req.Domain); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.Dir.SetPassword(r.Context(), req.Login, req.Password); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	accID, _ := strconv.ParseInt(r.URL.Query().Get("account_id"), 10, 64)
	var used, msgs int64
	s.Pool.QueryRow(r.Context(),
		`SELECT bytes_used, msg_count FROM quota_counters WHERE scope_type=1 AND scope_id=$1`, accID).Scan(&used, &msgs)
	var limit *int64
	s.Pool.QueryRow(r.Context(), `SELECT quota_bytes FROM accounts WHERE id=$1`, accID).Scan(&limit)
	resp := map[string]any{"account_id": accID, "bytes_used": used, "msg_count": msgs}
	if limit != nil {
		resp["bytes_limit"] = *limit
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	tid, _ := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	domain := r.URL.Query().Get("domain")
	var sent, complaints, bounces int64
	var paused bool
	err := s.Pool.QueryRow(r.Context(),
		`SELECT sent, complaints, bounces, paused FROM reputation_score WHERE tenant_id=$1 AND remote_domain=$2`,
		tid, domain).Scan(&sent, &complaints, &bounces, &paused)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tid, "domain": domain, "known": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": tid, "domain": domain, "known": true,
		"sent": sent, "complaints": complaints, "bounces": bounces, "paused": paused,
	})
}

// --- helpers ---

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusError is a client-safe error: its message is crafted for the client and
// carries an HTTP status. Any other error is treated as internal — logged, never
// echoed — so raw DB/driver text (constraint names, SQL, filesystem paths) can't
// leak to a caller.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

func errStatus(code int, msg string) error { return &statusError{code: code, msg: msg} }

// writeErr responds to a handler error. A *statusError yields its crafted message
// at its status; a pgx.ErrNoRows becomes a generic 400 (a bad reference in the
// request, safe to signal without detail); a unique-constraint violation becomes
// a 409 (the caller sent a duplicate — actionable, and the constraint name is not
// echoed); any other error is logged server-side (if Log is set) and the client
// gets a generic 500 with no internal detail — so raw DB/driver text can't leak.
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var se *statusError
	if errors.As(err, &se) {
		writeJSON(w, se.code, map[string]any{"error": se.msg})
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "not found"})
		return
	}
	// A unique-constraint violation is caller-caused (duplicate tenant/domain/
	// address), so signal it as a 409 rather than an opaque 500 — without echoing
	// the constraint name, which would leak schema detail.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "already exists"})
		return
	}
	if s.Log != nil {
		s.Log.WarnContext(r.Context(), "webadmin internal error", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
}
