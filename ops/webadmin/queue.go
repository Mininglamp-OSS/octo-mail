package webadmin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
)

// queueFilterReq is the common body for queue admin mutations: it selects which
// messages the operation targets. An empty request matches nothing (guarded
// below) — an operator must name ids, a tenant, an account, or a recipient.
type queueFilterReq struct {
	IDs       []int64 `json:"ids"`
	TenantID  int64   `json:"tenant_id"`
	AccountID int64   `json:"account_id"`
	Recipient string  `json:"recipient"`
}

func (q queueFilterReq) filter() queue.Filter {
	return queue.Filter{IDs: q.IDs, TenantID: q.TenantID, AccountID: q.AccountID, Recipient: q.Recipient}
}

func (q queueFilterReq) empty() bool {
	return len(q.IDs) == 0 && q.TenantID == 0 && q.AccountID == 0 && q.Recipient == ""
}

// filterReq is satisfied by queueFilterReq and any struct embedding it (the
// method set is promoted), so mutation handlers share one decode+guard path.
type filterReq interface {
	filter() queue.Filter
	empty() bool
}

// requireFilter decodes req (a pointer to a struct embedding queueFilterReq) and
// enforces a non-empty filter, writing the error response and returning false on
// failure. On success the caller reads any extra fields and runs the operation.
func requireFilter(w http.ResponseWriter, r *http.Request, req filterReq) bool {
	if !decode(w, r, req) {
		return false
	}
	if req.empty() {
		http.Error(w, "empty filter", http.StatusBadRequest)
		return false
	}
	return true
}

// writeCount writes {key: n} on success, or a 500 on error — the common tail of
// the count-returning queue mutations.
func writeCount(w http.ResponseWriter, key string, n int64, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{key: n})
}

// handleQueueList: GET /admin/queue?tenant_id=&account_id=&recipient=
func (s *Server) handleQueueList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	tid, _ := strconv.ParseInt(q.Get("tenant_id"), 10, 64)
	aid, _ := strconv.ParseInt(q.Get("account_id"), 10, 64)
	f := queue.Filter{TenantID: tid, AccountID: aid, Recipient: q.Get("recipient")}
	entries, err := queue.List(r.Context(), s.Pool, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"queue": entries})
}

// handleQueueKick: POST /admin/queue/kick — make matching messages due now.
func (s *Server) handleQueueKick(w http.ResponseWriter, r *http.Request) {
	var req queueFilterReq
	if !requireFilter(w, r, &req) {
		return
	}
	n, err := queue.Kick(r.Context(), s.Pool, req.filter())
	writeCount(w, "kicked", n, err)
}

// handleQueueHold: POST /admin/queue/hold {hold: bool, ...filter}
func (s *Server) handleQueueHold(w http.ResponseWriter, r *http.Request) {
	var req struct {
		queueFilterReq
		Hold bool `json:"hold"`
	}
	if !requireFilter(w, r, &req) {
		return
	}
	n, err := queue.HoldSet(r.Context(), s.Pool, req.filter(), req.Hold)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": n, "hold": req.Hold})
}

// handleQueueDrop: POST /admin/queue/drop — remove matching messages, no DSN.
func (s *Server) handleQueueDrop(w http.ResponseWriter, r *http.Request) {
	var req queueFilterReq
	if !requireFilter(w, r, &req) {
		return
	}
	n, err := queue.Drop(r.Context(), s.Pool, req.filter())
	writeCount(w, "dropped", n, err)
}

// handleQueueFail: POST /admin/queue/fail — remove matching messages and send a
// permanent-failure DSN for each (if QueueFailDSN is configured).
func (s *Server) handleQueueFail(w http.ResponseWriter, r *http.Request) {
	var req queueFilterReq
	if !requireFilter(w, r, &req) {
		return
	}
	n, err := queue.Fail(r.Context(), s.Pool, req.filter(), s.QueueFailDSN)
	writeCount(w, "failed", n, err)
}

// handleQueueSchedule: POST /admin/queue/schedule {delay: "30m", ...filter} —
// add a signed duration to matching messages' next_attempt.
func (s *Server) handleQueueSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		queueFilterReq
		Delay string `json:"delay"`
	}
	if !requireFilter(w, r, &req) {
		return
	}
	d, err := time.ParseDuration(req.Delay)
	if err != nil {
		http.Error(w, "bad delay", http.StatusBadRequest)
		return
	}
	n, err := queue.Schedule(r.Context(), s.Pool, req.filter(), d)
	writeCount(w, "scheduled", n, err)
}

// handleHoldRules: GET (list), POST (add), DELETE (remove) hold rules.
func (s *Server) handleHoldRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tid, _ := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
		rules, err := queue.HoldRuleList(r.Context(), s.Pool, tid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
	case http.MethodPost:
		var hr queue.HoldRule
		if err := json.NewDecoder(r.Body).Decode(&hr); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if hr.TenantID == 0 {
			http.Error(w, "tenant_id required", http.StatusBadRequest)
			return
		}
		id, held, err := queue.HoldRuleAdd(r.Context(), s.Pool, hr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "held": held})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if id == 0 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := queue.HoldRuleRemove(r.Context(), s.Pool, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": id})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleQueueScheduleAt: POST /admin/queue/schedule-at {at: RFC3339, ...filter} —
// set next_attempt to an absolute time.
func (s *Server) handleQueueScheduleAt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		queueFilterReq
		At string `json:"at"`
	}
	if !requireFilter(w, r, &req) {
		return
	}
	t, err := time.Parse(time.RFC3339, req.At)
	if err != nil {
		http.Error(w, "bad at (want RFC3339)", http.StatusBadRequest)
		return
	}
	n, err := queue.ScheduleAt(r.Context(), s.Pool, req.filter(), t)
	writeCount(w, "scheduled", n, err)
}

// handleQueueRequireTLS: POST /admin/queue/requiretls {mode: "policy"|"yes"|"no", ...filter}
func (s *Server) handleQueueRequireTLS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		queueFilterReq
		Mode string `json:"mode"` // "policy" (nil), "yes" (true), "no" (false)
	}
	if !requireFilter(w, r, &req) {
		return
	}
	var val *bool
	switch req.Mode {
	case "policy", "":
		val = nil
	case "yes", "true":
		t := true
		val = &t
	case "no", "false":
		f := false
		val = &f
	default:
		http.Error(w, "bad mode (want policy|yes|no)", http.StatusBadRequest)
		return
	}
	n, err := queue.RequireTLSSet(r.Context(), s.Pool, req.filter(), val)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": n, "mode": req.Mode})
}

// handleQueueRetired: GET /admin/queue/retired?tenant_id=&account_id= — list
// retired (delivered/failed) messages still within their retention window.
func (s *Server) handleQueueRetired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	tid, _ := strconv.ParseInt(q.Get("tenant_id"), 10, 64)
	aid, _ := strconv.ParseInt(q.Get("account_id"), 10, 64)
	entries, err := queue.RetiredList(r.Context(), s.Pool, queue.Filter{TenantID: tid, AccountID: aid})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retired": entries})
}

// handleQueueResults: GET /admin/queue/results?id= — per-attempt delivery history
// for one message id (live or retired).
func (s *Server) handleQueueResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if id == 0 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	results, err := queue.Results(r.Context(), s.Pool, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
