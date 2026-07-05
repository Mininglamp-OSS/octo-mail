package imapd_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestCrossNodeIdle is the P3 crown proof: two independent Store instances (two
// nodes) share one Postgres. A client IDLEs on node B; a delivery lands on node
// A; node B's IDLE must wake with an untagged EXISTS — carried across nodes by
// the coordinator (Postgres LISTEN/NOTIFY → changelog replay → Comm). No shared
// memory between the nodes; the change-log + doorbell are the only channel.
func TestCrossNodeIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two nodes = two Stores on the same DB, each with its own coordinator.
	nodeA := openNode(t, ctx, true)  // first node truncates for a clean slate
	nodeB := openNode(t, ctx, false) // second node shares the same DB

	// Seed schema data once (shared DB) via node A.
	var tenantID, accID, domID int64
	seed(t, nodeA, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	seed(t, nodeA, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	seed(t, nodeA, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	execN(t, nodeA, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	execN(t, nodeA, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)

	dirA := nodeA.NewDirectory()
	dirB := nodeB.NewDirectory()
	if err := dirB.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Pre-create the Inbox so SELECT on node B succeeds before any delivery.
	// (Deliver an initial message on node A to create Inbox, then read it away
	// is unnecessary — MailboxEnsure via a no-op: just deliver one seed message.)
	target0, err := dirA.ResolveInbound(ctx, mustPath(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target0.Deliver(ctx, &store.Message{}, memReader("Subject: seed\r\n\r\nseed\r\n")); err != nil {
		t.Fatal(err)
	}

	// Client connects to NODE B and IDLEs on INBOX.
	imapB := &imapd.Server{Dir: dirB}
	cliConn, srvConn := net.Pipe()
	go func() { _ = imapB.Serve(ctx, srvConn) }()
	_ = cliConn.SetDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReader(cliConn)
	readLine(t, br) // greeting
	sendLine(t, cliConn, "a login u1@example.com x")
	expectTagged(t, br, "a")
	sendLine(t, cliConn, "b select INBOX")
	expectTagged(t, br, "b")
	sendLine(t, cliConn, "c idle")
	// Expect the "+ idling" continuation.
	if l := readLine(t, br); !strings.HasPrefix(l, "+") {
		t.Fatalf("expected '+ idling', got %q", l)
	}

	// Now deliver a NEW message on NODE A. Node B's IDLE must wake.
	go func() {
		time.Sleep(150 * time.Millisecond)
		target, e := dirA.ResolveInbound(ctx, mustPath(t, "u1@example.com"))
		if e == nil {
			_, _ = target.Deliver(ctx, &store.Message{}, memReader("Subject: cross\r\n\r\ncross-node\r\n"))
		}
	}()

	// Read until we see an untagged EXISTS reflecting 2 messages (seed + new).
	got := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		l := readLine(t, br)
		if strings.HasPrefix(l, "* ") && strings.HasSuffix(l, "EXISTS") {
			got = true
			break
		}
	}
	if !got {
		t.Fatalf("node B IDLE did not receive EXISTS after node A delivery (cross-node notify failed)")
	}
	sendLine(t, cliConn, "DONE")
	t.Logf("OK: delivery on node A woke IDLE on node B via coordinator (LISTEN/NOTIFY + log replay)")
}

// --- helpers ---

func openNode(t *testing.T, ctx context.Context, truncate bool) *postgres.Store {
	t.Helper()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	if truncate {
		if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.StartCoordinator(ctx); err != nil {
		t.Fatalf("start coordinator: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func mustPath(t *testing.T, a string) smtp.Path {
	t.Helper()
	addr, err := smtp.ParseAddress(a)
	if err != nil {
		t.Fatal(err)
	}
	return addr.Path()
}

func sendLine(t *testing.T, w net.Conn, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s + "\r\n")); err != nil {
		t.Fatalf("send %q: %v", s, err)
	}
}

func readLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	l, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(l, "\r\n")
}

func expectTagged(t *testing.T, br *bufio.Reader, tag string) {
	t.Helper()
	for {
		l := readLine(t, br)
		if strings.HasPrefix(l, tag+" ") {
			if !strings.Contains(l, " OK") {
				t.Fatalf("command %s failed: %q", tag, l)
			}
			return
		}
	}
}

func seed(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("seed: %v", err)
	}
}
func execN(t *testing.T, s *postgres.Store, ctx context.Context, sql string, args ...any) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
