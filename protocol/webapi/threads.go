package webapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// GET /webapi/v0/threads/{id}
func (s *Server) getThread(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	tid, ok := parseThreadID(id)
	if !ok {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_id", "invalid thread id")
	}
	var out []messageSummary
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		// Push the thread filter into SQL (indexed) instead of scanning the account.
		msgs, e := tx.QueryMessage().FilterThread(tid).SortUID().List()
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
	if len(out) == 0 {
		return 0, nil, errStatus(http.StatusNotFound, "not_found", "no such thread")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ReceivedAt < out[j].ReceivedAt })
	return http.StatusOK, map[string]any{"id": id, "messages": out}, nil
}

func parseThreadID(id string) (int64, bool) {
	if len(id) < 2 || id[0] != 'T' {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil
}
