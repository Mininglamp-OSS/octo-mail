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

// TestCompressDeflate proves COMPRESS=DEFLATE (RFC 4978): after enabling
// compression the connection keeps working end-to-end — SELECT and FETCH over the
// deflate stream return the delivered message body, driven by the unmodified
// imapclient.CompressDeflate.
//
// Crucially this test uses a REAL TCP socket, not net.Pipe: net.Pipe is
// synchronous/unbuffered, so the deflate sync-flush the server writes can block
// when the client is mid-write — a test-harness artifact, not a protocol flaw. A
// real socket has kernel buffers, exactly like production.
func TestCompressDeflate(t *testing.T) {
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
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: compressed\r\n\r\nhello over deflate\r\n")); err != nil {
		t.Fatal(err)
	}

	// Real TCP listener + server goroutine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &imapd.Server{Dir: dir}
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.Serve(ctx, nc)
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	// Enable DEFLATE compression; all subsequent traffic is compressed both ways.
	if _, err := ic.CompressDeflate(); err != nil {
		t.Fatalf("CompressDeflate: %v", err)
	}
	// SELECT and FETCH now traverse the compressed stream.
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("SELECT over compression: %v", err)
	}
	if err := ic.WriteCommandf("", "uid fetch 1 (BODY[])"); err != nil {
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
				if b, ok := a.(imapclient.FetchBody); ok {
					body = b.Body
				}
			}
		}
	}
	if !strings.Contains(body, "hello over deflate") {
		t.Fatalf("FETCH over compression returned %q, want the message body", body)
	}

	// Enabling compression twice must be refused with [COMPRESSIONACTIVE].
	if err := ic.WriteCommandf("", "compress deflate"); err != nil {
		t.Fatal(err)
	}
	r2, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if string(r2.Result.Status) != "NO" {
		t.Fatalf("second COMPRESS should be refused, got %s %q", r2.Result.Status, r2.Result.Text)
	}

	t.Logf("OK: COMPRESS=DEFLATE over real TCP — SELECT+FETCH returned the body through the deflate stream; second COMPRESS refused")
}
