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

// TestMetadata proves IMAP METADATA (RFC 5464): SETMETADATA stores a per-mailbox
// entry and a server-level ("") entry; GETMETADATA reads them back (including
// prefix-subtree matching); NIL removes an entry. Driven by the imapclient via
// raw commands.
func TestMetadata(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, annotations RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	// A message so Inbox exists.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	cmd := func(c string) imapclient.Response {
		if err := ic.WriteCommandf("", "%s", c); err != nil {
			t.Fatal(err)
		}
		r, err := ic.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Per-mailbox entry.
	if r := cmd(`setmetadata INBOX (/private/comment "hello world")`); string(r.Result.Status) != "OK" {
		t.Fatalf("SETMETADATA: %s %q", r.Result.Status, r.Result.Text)
	}
	// Server-level entry ("" mailbox).
	if r := cmd(`setmetadata "" (/private/vendor/token "abc123")`); string(r.Result.Status) != "OK" {
		t.Fatalf("SETMETADATA server: %s %q", r.Result.Status, r.Result.Text)
	}

	// GET the per-mailbox entry.
	got := metadataResp(cmd(`getmetadata INBOX (/private/comment)`))
	if !strings.Contains(got, "/private/comment") || !strings.Contains(got, "hello world") {
		t.Fatalf("GETMETADATA INBOX = %q, want /private/comment=hello world", got)
	}
	// GET the server entry by subtree prefix (/private matches /private/vendor/token).
	gotSrv := metadataResp(cmd(`getmetadata "" (/private)`))
	if !strings.Contains(gotSrv, "/private/vendor/token") || !strings.Contains(gotSrv, "abc123") {
		t.Fatalf("GETMETADATA server subtree = %q, want vendor/token=abc123", gotSrv)
	}

	// Remove the per-mailbox entry with NIL; a subsequent GET returns nothing.
	if r := cmd(`setmetadata INBOX (/private/comment NIL)`); string(r.Result.Status) != "OK" {
		t.Fatalf("SETMETADATA NIL: %s", r.Result.Status)
	}
	gone := metadataResp(cmd(`getmetadata INBOX (/private/comment)`))
	if strings.Contains(gone, "hello world") {
		t.Fatalf("entry still present after NIL removal: %q", gone)
	}

	t.Logf("OK: SETMETADATA/GETMETADATA per-mailbox + server entries, subtree match, NIL removal")
}

// metadataResp concatenates the text of any untagged METADATA lines.
func metadataResp(r imapclient.Response) string {
	var b strings.Builder
	for _, u := range r.Untagged {
		if m, ok := u.(imapclient.UntaggedMetadataAnnotations); ok {
			for _, a := range m.Annotations {
				b.WriteString(a.Key + "=")
				b.Write(a.Value)
				b.WriteString(" ")
			}
		}
	}
	return b.String()
}
