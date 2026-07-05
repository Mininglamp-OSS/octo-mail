package postgres

import "errors"

var (
	errUnknownChange = errors.New("postgres: unknown change type")
	errNotFound      = errors.New("postgres: not found")
)
