package imapd_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// rawIMAP is a minimal line-based IMAP client for driving commands whose
// untagged responses (SORT, THREAD) the mox imapclient parser does not model.
type rawIMAP struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func newRawIMAP(t *testing.T, conn net.Conn) *rawIMAP {
	c := &rawIMAP{t: t, conn: conn, r: bufio.NewReader(conn)}
	c.readGreeting()
	return c
}

func (c *rawIMAP) readGreeting() {
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("greeting: %v", err)
	}
	if !strings.HasPrefix(line, "* OK") {
		c.t.Fatalf("greeting = %q", line)
	}
}

// cmd sends a tagged command and returns all untagged ("* ...") lines plus the
// final tagged status line.
func (c *rawIMAP) cmd(tag, command string) (untagged []string, tagged string) {
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, command); err != nil {
		c.t.Fatalf("write %q: %v", command, err)
	}
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read after %q: %v", command, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return untagged, line
		}
		if strings.HasPrefix(line, "* ") {
			untagged = append(untagged, line)
		}
	}
}

func (c *rawIMAP) mustOK(tag, command string) []string {
	un, tagged := c.cmd(tag, command)
	if !strings.Contains(tagged, " OK") {
		c.t.Fatalf("%q -> %q, want OK", command, tagged)
	}
	return un
}

// TestSortThreadListExtended drives SORT, THREAD, and LIST-EXTENDED over a real
// TCP socket. SORT/THREAD use a raw client (their untagged responses are not
// modeled by imapclient); LIST-EXTENDED is exercised via raw LIST commands so we
// can assert the \Subscribed / special-use / STATUS annotations directly.
func TestSortThreadListExtended(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, thread_refs, projection_cursor RESTART IDENTITY CASCADE`); err != nil {
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

	// Deliver 3 messages: two form a reply thread (subject "topic" / "Re: topic"
	// via In-Reply-To), one is standalone with a subject that sorts first.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(raw string) {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	deliver("From: carol@remote.example\r\nSubject: zeta\r\nMessage-ID: <a@x>\r\n\r\nfirst\r\n")
	deliver("From: alice@remote.example\r\nSubject: topic\r\nMessage-ID: <b@x>\r\n\r\nroot\r\n")
	deliver("From: bob@remote.example\r\nSubject: Re: topic\r\nMessage-ID: <c@x>\r\nIn-Reply-To: <b@x>\r\nReferences: <b@x>\r\n\r\nreply\r\n")

	// Run the thread projection so THREAD REFERENCES has thread_ids.
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("thread drain: %v", err)
	}

	// Start the server on a real TCP listener.
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
	rc.mustOK("a2", "select INBOX")

	// SORT by SUBJECT: base subjects are "zeta","topic","topic" → topic(2),topic(3),zeta(1).
	un := rc.mustOK("a3", "uid sort (subject) utf-8 all")
	sortLine := firstWithPrefix(t, un, "* SORT")
	if got := strings.TrimSpace(strings.TrimPrefix(sortLine, "* SORT")); got != "2 3 1" {
		t.Fatalf("SORT (SUBJECT) = %q, want \"2 3 1\"", got)
	}

	// SORT REVERSE SIZE: largest first. All small; just assert 3 ids returned.
	un = rc.mustOK("a4", "uid sort (reverse arrival) utf-8 all")
	sortLine = firstWithPrefix(t, un, "* SORT")
	if n := len(strings.Fields(strings.TrimPrefix(sortLine, "* SORT"))); n != 3 {
		t.Fatalf("SORT REVERSE ARRIVAL returned %d ids, want 3", n)
	}

	// THREAD REFERENCES: messages b(2) and c(3) thread together; a(1) alone.
	un = rc.mustOK("a5", "uid thread references utf-8 all")
	threadLine := firstWithPrefix(t, un, "* THREAD")
	body := strings.TrimSpace(strings.TrimPrefix(threadLine, "* THREAD"))
	// Expect one 2-member group (2 3) and one 1-member group (1), order by uid.
	if !strings.Contains(body, "(2 3)") {
		t.Fatalf("THREAD = %q, want a (2 3) group", body)
	}
	if strings.Count(body, "(") != 2 {
		t.Fatalf("THREAD = %q, want 2 groups", body)
	}

	// LIST-EXTENDED: subscribe to an Archive mailbox, then list with RETURN
	// (SUBSCRIBED CHILDREN) and assert annotations.
	rc.mustOK("a6", `create Archive`)
	rc.mustOK("a7", `subscribe Archive`)
	// Inbox is subscribed on delivery; create a child to test \HasChildren.
	rc.mustOK("a8", `create "Archive/2026"`)

	un = rc.mustOK("a9", `list "" "*" return (subscribed children)`)
	archiveLine := firstContaining(t, un, `"Archive"`)
	if !strings.Contains(archiveLine, `\Subscribed`) {
		t.Fatalf("LIST Archive missing \\Subscribed: %q", archiveLine)
	}
	if !strings.Contains(archiveLine, `\HasChildren`) {
		t.Fatalf("LIST Archive missing \\HasChildren: %q", archiveLine)
	}

	// LIST (SUBSCRIBED) selection: only subscribed mailboxes returned.
	un = rc.mustOK("a10", `list (subscribed) "" "*"`)
	for _, l := range un {
		if strings.Contains(l, `"Archive/2026"`) {
			t.Fatalf("LIST (SUBSCRIBED) returned unsubscribed child: %q", l)
		}
	}
	if firstContaining(t, un, `"Archive"`) == "" {
		t.Fatal("LIST (SUBSCRIBED) missing subscribed Archive")
	}

	// LIST RETURN (STATUS ...): per-mailbox STATUS folded into the LIST.
	un = rc.mustOK("a11", `list "" "INBOX" return (status (messages))`)
	if firstWithPrefix(t, un, "* STATUS") == "" {
		t.Fatal("LIST RETURN (STATUS) produced no STATUS line")
	}

	// UNSUBSCRIBE clears the flag.
	rc.mustOK("a12", `unsubscribe Archive`)
	un = rc.mustOK("a13", `list (subscribed) "" "*"`)
	for _, l := range un {
		if strings.Contains(l, `"Archive"`) && !strings.Contains(l, `"Archive/2026"`) {
			t.Fatalf("Archive still listed after unsubscribe: %q", l)
		}
	}

	t.Logf("OK: SORT (SUBJECT)=2 3 1, THREAD REFERENCES grouped (2 3), LIST-EXTENDED \\Subscribed/\\HasChildren + SUBSCRIBED selection + RETURN STATUS + unsubscribe, via real TCP")
}

func firstWithPrefix(t *testing.T, lines []string, prefix string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Fatalf("no line with prefix %q in %v", prefix, lines)
	return ""
}

func firstContaining(t *testing.T, lines []string, sub string) string {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}
