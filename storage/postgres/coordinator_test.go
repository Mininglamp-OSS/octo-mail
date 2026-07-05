package postgres_test

import (
	"context"
	"testing"
	"time"

	"io"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestCoordinatorCrossNode isolates the coordinator: two Stores (nodes) on one
// DB; a Comm registered on node B must receive changes for a delivery done on
// node A, carried by LISTEN/NOTIFY + log replay.
func TestCoordinatorCrossNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	open := func(truncate bool) *postgres.Store {
		bs, _ := blob.NewFS(t.TempDir())
		s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
		if err != nil {
			t.Skipf("postgres not available (%v)", err)
		}
		if truncate {
			s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`)
		}
		if err := s.StartCoordinator(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	a := open(true)
	b := open(false)

	var tenantID, accID, domID int64
	a.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	a.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	a.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	a.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)

	// Register a Comm on node B for the account.
	accB := b.OpenAccountForTest(accID, tenantID, "u1")
	comm := accB.RegisterComm()
	defer comm.Close()

	// Deliver on node A.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := a.NewDirectory().ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case changes := <-comm.Changes:
		if len(changes) == 0 {
			t.Fatalf("empty change batch")
		}
		t.Logf("OK: node B Comm received %d changes from node A delivery", len(changes))
	case <-time.After(8 * time.Second):
		t.Fatalf("node B Comm did not receive cross-node changes")
	}
}

func memBytes(s string) store.BlobReader { return &mb{data: []byte(s)} }

type mb struct {
	data []byte
	off  int64
}

func (m *mb) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *mb) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	return copy(p, m.data[off:]), nil
}
func (m *mb) Size() int64  { return int64(len(m.data)) }
func (m *mb) Close() error { return nil }
