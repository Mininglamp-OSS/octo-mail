package webapi

import (
	"context"
	"net/http"
)

// GET /webapi/v0/suppressions
func (s *Server) listSuppressions(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Suppressions == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "suppressions not enabled")
	}
	list, err := s.Suppressions.List(ctx, a.acc.ID())
	if err != nil {
		return 0, nil, internalErr("internal", err)
	}
	if list == nil {
		list = []string{}
	}
	return http.StatusOK, map[string]any{"suppressions": list}, nil
}

// GET /webapi/v0/suppressions/{address} — presence check.
func (s *Server) getSuppression(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Suppressions == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "suppressions not enabled")
	}
	addr := r.PathValue("address")
	present, err := s.Suppressions.Suppressed(ctx, a.acc.ID(), addr)
	if err != nil {
		return 0, nil, internalErr("internal", err)
	}
	if !present {
		return 0, nil, errStatus(http.StatusNotFound, "not_found", "not suppressed")
	}
	return http.StatusOK, map[string]any{"address": addr, "suppressed": true}, nil
}

// suppressionBody is the optional body for PUT (a reason).
type suppressionBody struct {
	Reason string `json:"reason,omitempty"`
}

// PUT /webapi/v0/suppressions/{address} — add (idempotent).
func (s *Server) putSuppression(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Suppressions == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "suppressions not enabled")
	}
	addr := r.PathValue("address")
	var body suppressionBody
	_ = decode(r, &body) // body optional; ignore decode error on empty
	if err := s.Suppressions.Add(ctx, a.scope.Tenant().ID, a.acc.ID(), addr, body.Reason); err != nil {
		return 0, nil, internalErr("internal", err)
	}
	return http.StatusOK, map[string]any{"address": addr, "suppressed": true}, nil
}

// DELETE /webapi/v0/suppressions/{address}
func (s *Server) deleteSuppression(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Suppressions == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "suppressions not enabled")
	}
	addr := r.PathValue("address")
	if err := s.Suppressions.Remove(ctx, a.acc.ID(), addr); err != nil {
		return 0, nil, internalErr("internal", err)
	}
	return http.StatusNoContent, nil, nil
}
