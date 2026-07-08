package postgres

import (
	"context"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// OpenAccountForTest opens an account handle by id for tests only (this file is
// compiled solely under `go test`). Production code uses OpenAccountByID /
// LookupAccountByID in accessors.go.
func (s *Store) OpenAccountForTest(id, tenantID int64, name string) store.Account {
	return s.openAccount(id, tenantID, name)
}

// ResyncAllForTest exposes resyncAll to tests (the post-reconnect recovery that
// replays missed notifications to local subscribers).
func (s *Store) ResyncAllForTest(ctx context.Context) { s.resyncAll(ctx) }
