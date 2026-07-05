package smtpd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestSMTPSizeAndPipelining proves the SIZE (RFC 1870) and PIPELINING (RFC 2920)
// ESMTP extensions: EHLO advertises both; an oversized SIZE= on MAIL FROM is
// rejected early with 552 (before DATA); and a real client (the smtpclient,
// which pipelines) still delivers a normal message.
func TestSMTPSizeAndPipelining(t *testing.T) {
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
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	// MX with a 1000-byte max size.
	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", MaxSize: 1000}

	// --- 1. EHLO advertises SIZE + PIPELINING; oversized SIZE= rejected 552. ---
	func() {
		cc, sc := net.Pipe()
		go func() { _ = mx.Serve(ctx, sc) }()
		defer cc.Close()
		_ = cc.SetDeadline(time.Now().Add(10 * time.Second))
		br := newLineReader(cc)
		_ = br.line() // 220 greeting
		cc.Write([]byte("EHLO client.example\r\n"))
		var ehlo []string
		for {
			l := br.line()
			ehlo = append(ehlo, l)
			if len(l) < 4 || l[3] == ' ' { // last line "250 ..."
				break
			}
		}
		joined := strings.Join(ehlo, "\n")
		if !strings.Contains(joined, "SIZE 1000") {
			t.Fatalf("EHLO missing 'SIZE 1000':\n%s", joined)
		}
		if !strings.Contains(joined, "PIPELINING") {
			t.Fatalf("EHLO missing PIPELINING:\n%s", joined)
		}
		// Oversized declared size → 552 before DATA.
		cc.Write([]byte("MAIL FROM:<a@remote.example> SIZE=5000\r\n"))
		resp := br.line()
		if !strings.HasPrefix(resp, "552") {
			t.Fatalf("oversized SIZE= got %q, want 552", resp)
		}
		cc.Write([]byte("QUIT\r\n"))
	}()

	// --- 2. A real (pipelining) client delivers a normal message. ---
	cConn, sConn := net.Pipe()
	go func() { _ = mx.Serve(ctx, sConn) }()
	_ = cConn.SetDeadline(time.Now().Add(15 * time.Second))
	cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
		dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
	if err != nil {
		t.Fatalf("smtpclient: %v", err)
	}
	defer cl.Close()
	msg := "From: a@remote.example\r\nTo: u1@example.com\r\nSubject: sized\r\n\r\nsmall body\r\n"
	if err := cl.Deliver(ctx, "a@remote.example", "u1@example.com", int64(len(msg)), strings.NewReader(msg), false, false, false); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, accID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 delivered message, got %d", n)
	}

	t.Logf("OK: EHLO advertises SIZE 1000 + PIPELINING; oversized SIZE= rejected 552 pre-DATA; real client delivered normally")
}

// lineReader reads CRLF-terminated lines from a conn.
type lineReader struct {
	c   net.Conn
	buf []byte
}

func newLineReader(c net.Conn) *lineReader { return &lineReader{c: c} }

func (r *lineReader) line() string {
	for {
		if i := indexCRLF(r.buf); i >= 0 {
			l := string(r.buf[:i])
			r.buf = r.buf[i+2:]
			return l
		}
		tmp := make([]byte, 512)
		n, err := r.c.Read(tmp)
		if n > 0 {
			r.buf = append(r.buf, tmp[:n]...)
		}
		if err != nil {
			l := string(r.buf)
			r.buf = nil
			return l
		}
	}
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}
