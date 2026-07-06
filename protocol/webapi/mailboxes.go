package webapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// mailboxInfo is the list-view shape of a mailbox.
type mailboxInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Total  int64  `json:"total"`
	Unread int64  `json:"unread"`
}

// GET /webapi/v0/mailboxes
func (s *Server) listMailboxes(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var out []mailboxInfo
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		mbs, e := tx.QueryMailbox().List()
		if e != nil {
			return e
		}
		for _, mb := range mbs {
			out = append(out, mailboxInfo{
				ID:     strconv.FormatInt(mb.ID, 10),
				Name:   mb.Name,
				Total:  mb.Total,
				Unread: mb.Unread,
			})
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if out == nil {
		out = []mailboxInfo{}
	}
	return http.StatusOK, map[string]any{"mailboxes": out}, nil
}
