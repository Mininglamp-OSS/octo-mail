package mailboxops_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/ops/mailboxops"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

const dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func mem(s string) store.BlobReader { return &memBlob{data: []byte(s)} }

type memBlob struct {
	data []byte
	off  int64
}

func (m *memBlob) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *memBlob) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memBlob) Size() int64  { return int64(len(m.data)) }
func (m *memBlob) Close() error { return nil }

// TestMboxRoundTrip proves WF-G backup/restore: deliver messages to an account,
// export the mailbox to mbox, import that mbox into a second account, and verify
// the message bodies survive the round trip (including "From " line escaping).
func TestMboxRoundTrip(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, dsn, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tid, srcID, dstID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tid)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'src') RETURNING id`, tid).Scan(&srcID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'dst') RETURNING id`, tid).Scan(&dstID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tid).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'src')`, tid, domID, srcID)

	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("src@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Include a body line beginning with "From " to exercise mboxrd escaping.
	bodies := []string{
		"Subject: one\r\n\r\nhello world\r\n",
		"Subject: two\r\n\r\nFrom the desk of the CEO\r\nsecond line\r\n",
	}
	for _, b := range bodies {
		if _, err := target.Deliver(ctx, &store.Message{}, mem(b)); err != nil {
			t.Fatal(err)
		}
	}

	// Export src Inbox to mbox.
	srcAcc, err := s.OpenAccountForOps(ctx, "t", "src")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := mailboxops.ExportMbox(ctx, srcAcc, "Inbox", &buf)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if n != 2 {
		t.Fatalf("exported %d, want 2", n)
	}
	// The escaped "From " line must appear as ">From " in the mbox stream.
	if !strings.Contains(buf.String(), ">From the desk") {
		t.Fatalf("mboxrd escaping missing; mbox:\n%s", buf.String())
	}

	// Import into dst Inbox.
	dstAcc, err := s.OpenAccountForOps(ctx, "t", "dst")
	if err != nil {
		t.Fatal(err)
	}
	m, err := mailboxops.ImportMbox(ctx, dstAcc, "Inbox", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if m != 2 {
		t.Fatalf("imported %d, want 2", m)
	}

	// Verify dst has 2 messages and the "From " line was unescaped back.
	var cnt int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, dstID).Scan(&cnt)
	if cnt != 2 {
		t.Fatalf("dst has %d messages, want 2", cnt)
	}
	var found bool
	err = dstAcc.Tx(ctx, func(tx store.Tx) error {
		mb, _ := dstAcc.MailboxFind(tx, "Inbox")
		msgs, _ := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		for _, msg := range msgs {
			r := dstAcc.MessageReader(ctx, msg)
			data := make([]byte, msg.Size)
			off := 0
			for off < len(data) {
				k, e := r.Read(data[off:])
				off += k
				if e != nil {
					break
				}
			}
			r.Close()
			if strings.Contains(string(data[:off]), "From the desk of the CEO") &&
				!strings.Contains(string(data[:off]), ">From the desk") {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("imported message did not preserve/unescape the \"From \" body line")
	}
	t.Logf("OK: exported 2 msgs to mbox (>From escaped), imported into dst (From unescaped), bodies round-tripped")
}
