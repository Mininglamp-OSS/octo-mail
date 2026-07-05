package imapd_test

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestBinaryFetch proves IMAP BINARY (RFC 3516): FETCH BINARY[1] returns the
// part's body decoded from its Content-Transfer-Encoding (base64 → raw octets),
// and BINARY.SIZE[1] returns the decoded octet count. Driven by the imapclient.
func TestBinaryFetch(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
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
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// A single-part message whose body is base64-encoded binary content.
	payload := []byte("binary\x00\x01\x02content here")
	b64 := base64.StdEncoding.EncodeToString(payload)
	msg := "From: a@remote.example\r\nTo: u1@example.com\r\nSubject: bin\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n"
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(msg)); err != nil {
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
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}

	// FETCH BINARY[1]: body decoded from base64 → exact original octets.
	if err := ic.WriteCommandf("", "uid fetch 1 (BINARY[1])"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, u := range resp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if b, ok := a.(imapclient.FetchBinary); ok {
					body = b.Data
				}
			}
		}
	}
	if body != string(payload) {
		t.Fatalf("BINARY[1] = %q, want decoded %q", body, string(payload))
	}

	// BINARY.SIZE[1] returns the decoded octet count.
	if err := ic.WriteCommandf("", "uid fetch 1 (BINARY.SIZE[1])"); err != nil {
		t.Fatal(err)
	}
	r2, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	gotSize := -1
	for _, u := range r2.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if bs, ok := a.(imapclient.FetchBinarySize); ok {
					gotSize = int(bs.Size)
				}
			}
		}
	}
	if gotSize != len(payload) {
		t.Fatalf("BINARY.SIZE[1] = %d, want %d", gotSize, len(payload))
	}

	t.Logf("OK: BINARY[1] decoded base64 body to %d raw octets; BINARY.SIZE[1]=%d", len(payload), gotSize)
}
