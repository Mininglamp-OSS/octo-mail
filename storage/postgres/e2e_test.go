package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/smtp"
)

// dsn for the local test Postgres (see docker container octo-mail-pg).
const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// setupTest opens the store against a freshly-truncated schema and a temp-dir
// blob store, and seeds one tenant/account/domain/address.
func setupTest(t *testing.T) (*Store, *Directory, int64) {
	t.Helper()
	ctx := context.Background()

	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("blob fs: %v", err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v); start: docker run -d --name octo-mail-pg -e POSTGRES_PASSWORD=octo-mail -e POSTGRES_USER=octo-mail -e POSTGRES_DB=octo-mail -p 55432:5432 postgres:17", err)
	}
	t.Cleanup(s.Close)

	// Clean slate.
	_, err = s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}

	var tenantID, accID, domID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID))
	_, err = s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	must(t, err)

	return s, s.NewDirectory(), accID
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

// TestDeliverReadFlagAndModseq is the P1 milestone end-to-end test: deliver a
// message via the inbound (directory) path, read it back through the account
// kernel, mark \Seen, and assert the core invariant — IMAP HIGHESTMODSEQ (the
// account changelog head) equals max(changelog.seq).
func TestDeliverReadFlagAndModseq(t *testing.T) {
	ctx := context.Background()
	s, dir, accID := setupTest(t)

	// Inbound delivery via the directory (no principal, address-resolved).
	target, err := resolveInbound(t, dir, "u1@example.com")
	if err != nil {
		t.Fatalf("resolve inbound: %v", err)
	}
	body := "From: a@remote.example\r\nTo: u1@example.com\r\nSubject: hello\r\n\r\nhi there\r\n"
	m := &store.Message{}
	if _, err := target.Deliver(ctx, m, memReader(body)); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	acc := s.openAccount(accID, target.Tenant().ID, "u1")

	// Read it back: Inbox should have exactly one message with the right size.
	var got store.Message
	err = acc.Tx(ctx, func(tx store.Tx) error {
		mb, err := acc.MailboxFind(tx, "Inbox")
		if err != nil || mb == nil {
			t.Fatalf("inbox missing: %v", err)
		}
		msgs, err := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		if err != nil {
			return err
		}
		if len(msgs) != 1 {
			t.Fatalf("got %d messages, want 1", len(msgs))
		}
		got = msgs[0]
		return nil
	})
	if err != nil {
		t.Fatalf("read tx: %v", err)
	}
	if got.Seen {
		t.Fatalf("new message should be unseen")
	}
	if got.UID != 1 {
		t.Fatalf("first message UID = %d, want 1", got.UID)
	}

	// Read the body back through the blob store (prefix + body).
	r := acc.MessageReader(ctx, got)
	buf := make([]byte, got.Size+16)
	n, _ := readFull(r, buf)
	r.Close()
	if !strings.Contains(string(buf[:n]), "hi there") {
		t.Fatalf("body readback missing content: %q", string(buf[:n]))
	}

	// Mark \Seen — one ChangeFlags entry, advancing modseq.
	err = acc.Tx(ctx, func(tx store.Tx) error {
		got.Seen = true
		return tx.Update(&got)
	})
	if err != nil {
		t.Fatalf("set seen: %v", err)
	}

	// THE INVARIANT: account changelog head == max(changelog.seq).
	var head, maxSeq int64
	must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&head))
	must(t, s.Pool.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, accID).Scan(&maxSeq))
	if head != maxSeq {
		t.Fatalf("HIGHESTMODSEQ invariant broken: head=%d max(seq)=%d", head, maxSeq)
	}
	if head < 3 {
		// At least: mailbox_create(Inbox) + add_uid + flags_set.
		t.Fatalf("expected >=3 log entries, head=%d", head)
	}

	// Verify \Seen persisted.
	err = acc.Tx(ctx, func(tx store.Tx) error {
		var m2 store.Message
		m2.ID = got.ID
		if err := tx.Get(&m2); err != nil {
			return err
		}
		if !m2.Seen {
			t.Fatalf("seen flag not persisted")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify tx: %v", err)
	}

	t.Logf("OK: changelog head=%d == max(seq)=%d; message UID=%d size=%d", head, maxSeq, got.UID, got.Size)
}

// TestReplayRebuildsHead proves the log is the source of truth: max(changelog.seq)
// alone reconstructs HIGHESTMODSEQ (a stand-in for full projection rebuild).
func TestReplayRebuildsHead(t *testing.T) {
	ctx := context.Background()
	s, dir, accID := setupTest(t)
	target, err := resolveInbound(t, dir, "u1@example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: m\r\n\r\nbody\r\n")); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}
	var head, maxSeq int64
	must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&head))
	must(t, s.Pool.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, accID).Scan(&maxSeq))
	if head != maxSeq {
		t.Fatalf("head=%d != max(seq)=%d", head, maxSeq)
	}
}

// --- helpers ---

func resolveInbound(t *testing.T, dir *Directory, addr string) (directory.InboundTarget, error) {
	t.Helper()
	p, err := smtp.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	return dir.ResolveInbound(context.Background(), p.Path())
}

// memReader is an in-memory BlobReader over a string body.
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

// readFull reads until buf is full or EOF, returning bytes read.
func readFull(r store.BlobReader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
