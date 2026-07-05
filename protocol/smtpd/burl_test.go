package smtpd_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestBURL proves the BURL (RFC 4468) submission path, closing the URLAUTH loop:
// a message composed on the IMAP server is submitted for outbound delivery
// without the client downloading and re-uploading it. IMAP GENURLAUTH mints an
// authorized URL; SMTP BURL resolves it via the shared store and enqueues the
// referenced content.
func TestBURL(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, senderID, sdom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &senderID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &sdom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	// Compose the outbound message into the sender's INBOX (as if saved via IMAP).
	target, err := dir.ResolveInbound(ctx, mustPath(t, "me@sender.example"))
	if err != nil {
		t.Fatal(err)
	}
	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: burl\r\n\r\ncomposed on server\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
		t.Fatal(err)
	}

	// --- Mint an authorized URL over IMAP (GENURLAUTH), driven raw. ---
	imapSrv := &imapd.Server{Dir: dir}
	ic, is := net.Pipe()
	go func() { _ = imapSrv.Serve(ctx, is) }()
	_ = ic.SetDeadline(time.Now().Add(15 * time.Second))
	ibr := bufio.NewReader(ic)
	_, _ = ibr.ReadString('\n') // greeting
	authURL := imapGenURLAuth(t, ic, ibr, "imap://me@sender.example/INBOX/;UID=1;URLAUTH=submit+me")
	_ = ic.Close()

	// --- Submission server with BURL resolver wired (as cmd/octo-mail does). ---
	sub := &smtpd.Server{
		Dir:        dir,
		Hostname:   "mail.sender.example",
		Submission: &submit.Submitter{Pool: s.Pool, Blob: bs},
		BURLResolver: func(ctx context.Context, accountID int64, u string) ([]byte, bool) {
			acc, _, _, err := s.LookupAccountByID(ctx, accountID)
			if err != nil {
				return nil, false
			}
			return imapd.ResolveURLAuth(ctx, acc, u)
		},
	}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // 220

	cc.Write([]byte("EHLO client.example\r\n"))
	var ehlo []string
	for {
		l := br.line()
		ehlo = append(ehlo, l)
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	if !strings.Contains(strings.Join(ehlo, "\n"), "BURL") {
		t.Fatalf("EHLO missing BURL:\n%s", strings.Join(ehlo, "\n"))
	}

	// AUTH PLAIN me@sender.example.
	authTok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + authTok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q, want 235", r)
	}
	cc.Write([]byte("MAIL FROM:<me@sender.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %q", r)
	}
	cc.Write([]byte("RCPT TO:<you@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT: %q", r)
	}

	// BURL with the authorized URL + LAST → server fetches the content and enqueues.
	fmt.Fprintf(cc, "BURL %s LAST\r\n", authURL)
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("BURL: %q, want 250", r)
	}
	var q int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("expected 1 queued outbound after BURL, got %d", q)
	}

	// A tampered URL must be refused (554) and enqueue nothing more.
	cc.Write([]byte("MAIL FROM:<me@sender.example>\r\n"))
	_ = br.line()
	cc.Write([]byte("RCPT TO:<you@remote.example>\r\n"))
	_ = br.line()
	bad := authURL[:len(authURL)-1] + "0"
	if authURL[len(authURL)-1] == '0' {
		bad = authURL[:len(authURL)-1] + "1"
	}
	fmt.Fprintf(cc, "BURL %s LAST\r\n", bad)
	if r := br.line(); !strings.HasPrefix(r, "554") {
		t.Fatalf("tampered BURL: %q, want 554", r)
	}
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM queue`).Scan(&q)
	if q != 1 {
		t.Fatalf("tampered BURL enqueued a message (queue=%d)", q)
	}
	cc.Write([]byte("QUIT\r\n"))

	t.Logf("OK: GENURLAUTH minted URL, SMTP BURL resolved+enqueued it (queue=1), tampered URL → 554 (no enqueue)")
}

// imapGenURLAuth issues GENURLAUTH over a raw IMAP connection and returns the
// authorized URL from the untagged response.
func imapGenURLAuth(t *testing.T, c net.Conn, br *bufio.Reader, rump string) string {
	fmt.Fprintf(c, "x1 LOGIN me@sender.example pw\r\n")
	readToTagged(t, br, "x1")
	fmt.Fprintf(c, "x2 GENURLAUTH %q INTERNAL\r\n", rump)
	var url string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("genurlauth read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "* GENURLAUTH ") {
			url = strings.Trim(strings.TrimPrefix(line, "* GENURLAUTH "), `"`)
		}
		if strings.HasPrefix(line, "x2 ") {
			break
		}
	}
	if url == "" || !strings.Contains(url, ":internal:") {
		t.Fatalf("GENURLAUTH returned no URL")
	}
	return url
}

func readToTagged(t *testing.T, br *bufio.Reader, tag string) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read tag %s: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return
		}
	}
}

func mustPath(t *testing.T, a string) smtp.Path {
	addr, err := smtp.ParseAddress(a)
	if err != nil {
		t.Fatal(err)
	}
	return addr.Path()
}

// memReader adapts a string to a store.BlobReader for InboundTarget.Deliver.
func memReader(s string) store.BlobReader {
	return &memBlob{Reader: bytes.NewReader([]byte(s)), size: int64(len(s))}
}

type memBlob struct {
	*bytes.Reader
	size int64
}

func (b *memBlob) Close() error { return nil }
func (b *memBlob) Size() int64  { return b.size }
