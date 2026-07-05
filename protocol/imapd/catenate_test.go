package imapd_test

import (
	"context"
	"fmt"
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

// TestCatenate drives CATENATE (RFC 4469): APPEND assembles a new message
// server-side from a TEXT literal concatenated with a URL part that references
// the TEXT section of an existing message (IMAP URL, RFC 5092). The CATENATE
// command is issued raw (imapclient does not model it); the assembled result is
// read back with the unmodified imapclient via FETCH BODY[].
func TestCatenate(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Source message: its TEXT section is "SOURCEBODY\r\n".
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("From: a@remote.example\r\nSubject: src\r\n\r\nSOURCEBODY\r\n")); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &imapd.Server{Dir: dir}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.Serve(ctx, nc) }()
		}
	}()

	// --- Issue CATENATE raw. ---
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, conn)
	rc.mustOK("a1", "login u1@example.com x")
	rc.mustOK("a2", "select INBOX")

	// APPEND with CATENATE: a literal prefix + the source message's TEXT section.
	// A non-synchronizing literal {n+} lets the whole command be one write.
	prefix := "PREFIX-"
	cmd := fmt.Sprintf("a3 APPEND INBOX CATENATE (TEXT {%d+}\r\n%s URL \"/INBOX;UID=1/;SECTION=TEXT\")\r\n", len(prefix), prefix)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		t.Fatal(err)
	}
	if tagged := readToTag(t, rc, "a3"); !strings.Contains(tagged, " OK") {
		t.Fatalf("CATENATE APPEND -> %q, want OK", tagged)
	}

	// --- Read the assembled message back with the real imapclient. ---
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(30 * time.Second))
	ic, err := imapclient.New(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatalf("login2: %v", err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("select2: %v", err)
	}
	if err := ic.WriteCommandf("", "uid fetch 2 (BODY[])"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatalf("fetch assembled: %v", err)
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
	if !strings.Contains(body, "PREFIX-") {
		t.Fatalf("assembled message missing literal prefix: %q", body)
	}
	if !strings.Contains(body, "SOURCEBODY") {
		t.Fatalf("assembled message missing URL-referenced section: %q", body)
	}

	t.Logf("OK: CATENATE assembled a message from a TEXT literal + a URL-referenced section: %q", strings.TrimSpace(body))
}

// readToTag reads lines from the raw client until the given tag's completion.
func readToTag(t *testing.T, rc *rawIMAP, tag string) string {
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read to tag %s: %v", tag, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return line
		}
	}
}
