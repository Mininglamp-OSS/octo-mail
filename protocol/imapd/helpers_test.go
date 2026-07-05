package imapd_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func mustScan(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
}

func mustAddr(t *testing.T, a string) smtp.Path {
	t.Helper()
	addr, err := smtp.ParseAddress(a)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	return addr.Path()
}

func memReader(s string) store.BlobReader {
	return &memBlob{r: strings.NewReader(s), size: int64(len(s))}
}

type memBlob struct {
	r    *strings.Reader
	size int64
}

func (m *memBlob) Read(b []byte) (int, error)              { return m.r.Read(b) }
func (m *memBlob) ReadAt(b []byte, off int64) (int, error) { return m.r.ReadAt(b, off) }
func (m *memBlob) Size() int64                             { return m.size }
func (m *memBlob) Close() error                            { return nil }
