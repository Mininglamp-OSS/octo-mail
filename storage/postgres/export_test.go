package postgres

import "github.com/Mininglamp-OSS/octo-mail/core/store"

// OpenAccountForTest opens an account handle by id for tests only (this file is
// compiled solely under `go test`). Production code uses OpenAccountByID /
// LookupAccountByID in accessors.go.
func (s *Store) OpenAccountForTest(id, tenantID int64, name string) store.Account {
	return s.openAccount(id, tenantID, name)
}
