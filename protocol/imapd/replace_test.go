package imapd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestReplace proves P1-3 IMAP REPLACE (RFC 8508): a UID REPLACE atomically
// appends a new message and expunges the referenced source, leaving exactly one
// message (the replacement) in the mailbox — never zero, never two.
func TestReplace(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: original\r\n\r\noriginal body\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	cc, scpipe := net.Pipe()
	go func() { _ = srv.Serve(ctx, scpipe) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}

	// UID REPLACE uid 1 in INBOX with a new message, using a non-sync literal.
	replacement := "Subject: replacement\r\n\r\nreplacement body\r\n"
	if err := ic.WriteCommandf("", "uid replace 1 INBOX {%d+}\r\n%s", len(replacement), replacement); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Result.Status) != "OK" {
		t.Fatalf("REPLACE result = %s %q, want OK", resp.Result.Status, resp.Result.Text)
	}

	// Exactly one message remains, and it is the replacement (original expunged).
	var count int
	mustScan(t, s, ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, &count, accID)
	if count != 1 {
		t.Fatalf("after REPLACE, non-expunged messages = %d, want 1", count)
	}
	// Fetch the surviving message body to confirm it is the replacement.
	if err := ic.WriteCommandf("", "uid fetch 1:* (BODY[])"); err != nil {
		t.Fatal(err)
	}
	fresp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, u := range fresp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if b, ok := a.(imapclient.FetchBody); ok {
					body = b.Body
				}
			}
		}
	}
	if !strings.Contains(body, "replacement body") || strings.Contains(body, "original body") {
		t.Fatalf("surviving message body = %q, want the replacement", body)
	}

	t.Logf("OK: UID REPLACE atomically swapped the message (1 remains: the replacement, original expunged)")
}
