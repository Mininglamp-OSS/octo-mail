package imapd_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestURLAuth drives URLAUTH (RFC 4467): GENURLAUTH mints an authorized URL bound
// to the mailbox key; URLFETCH returns the referenced section for a valid token,
// NIL for a tampered token; RESETKEY rotates the key and revokes prior URLs.
// Driven raw — imapclient models none of these commands.
func TestURLAuth(t *testing.T) {
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

	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("From: a@remote.example\r\nSubject: src\r\n\r\nURLAUTHBODY\r\n")); err != nil {
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

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, conn)
	rc.mustOK("a1", "login u1@example.com x")

	// GENURLAUTH mints an authorized URL for the INBOX message's TEXT section.
	rump := `imap://u1@example.com/INBOX/;UID=1/;SECTION=TEXT;URLAUTH=user+u1`
	un := rc.mustOK("a2", fmt.Sprintf("GENURLAUTH %q INTERNAL", rump))
	authURL := ""
	for _, l := range un {
		if strings.HasPrefix(l, "* GENURLAUTH ") {
			authURL = strings.Trim(strings.TrimPrefix(l, "* GENURLAUTH "), `"`)
		}
	}
	if authURL == "" || !strings.Contains(authURL, ":internal:") {
		t.Fatalf("GENURLAUTH did not return an authorized URL: %v", un)
	}

	// URLFETCH with the valid URL returns the referenced section as a literal.
	body := urlfetch(t, rc, conn, "a3", authURL)
	if !strings.Contains(body, "URLAUTHBODY") {
		t.Fatalf("URLFETCH returned %q, want the TEXT section", body)
	}

	// Tampering the token → NIL (no content leaked).
	bad := authURL[:len(authURL)-1] + flipHex(authURL[len(authURL)-1])
	if got := urlfetch(t, rc, conn, "a4", bad); got != "" {
		t.Fatalf("URLFETCH with tampered token returned data %q, want NIL", got)
	}

	// RESETKEY rotates the mailbox key → the previously-minted URL is revoked.
	rc.mustOK("a5", "RESETKEY INBOX")
	if got := urlfetch(t, rc, conn, "a6", authURL); got != "" {
		t.Fatalf("URLFETCH after RESETKEY returned data %q, want NIL (revoked)", got)
	}

	t.Logf("OK: GENURLAUTH minted a token, URLFETCH returned the section, tampered token → NIL, RESETKEY revoked the URL")
}

// urlfetch issues URLFETCH and returns the literal body, or "" for a NIL result.
func urlfetch(t *testing.T, rc *rawIMAP, conn net.Conn, tag, url string) string {
	if _, err := fmt.Fprintf(conn, "%s URLFETCH %q\r\n", tag, url); err != nil {
		t.Fatal(err)
	}
	var body string
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("urlfetch read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return body
		}
		if strings.HasPrefix(line, "* URLFETCH ") {
			// Ends with " {n}" (literal follows) or " NIL".
			if strings.HasSuffix(line, " NIL") {
				continue
			}
			if i := strings.LastIndex(line, "{"); i >= 0 {
				n, _ := strconv.Atoi(strings.TrimSuffix(line[i+1:], "}"))
				buf := make([]byte, n)
				if _, err := readFull(rc.r, buf); err != nil {
					t.Fatalf("urlfetch literal: %v", err)
				}
				body = string(buf)
			}
		}
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
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

func flipHex(b byte) string {
	if b == '0' {
		return "1"
	}
	return "0"
}
