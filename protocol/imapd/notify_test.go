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
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestNotify proves IMAP NOTIFY (RFC 5465): after NOTIFY SET on the selected
// mailbox, an unsolicited EXISTS is pushed to the client when a message is
// delivered by another path — without the client being in IDLE. Uses a raw
// line client over real TCP (the pusher writes concurrently with the command
// loop, which net.Pipe would deadlock).
func TestNotify(t *testing.T) {
	// Cancelable ctx so the coordinator's LISTEN connection is released before
	// s.Close(): pgxpool.Close() blocks until every checked-out conn is returned,
	// and listenLoop holds one until ctx is cancelled. defer runs LIFO, so cancel
	// (declared after s.Close) fires first.
	ctx, cancel := context.WithCancel(context.Background())
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		cancel()
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	defer cancel() // LIFO: cancel first, releasing the coordinator's LISTEN conn, then s.Close()
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
	// Seed one message so INBOX exists and SELECT succeeds.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: seed\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}

	// Start coordinator so cross-path deliveries reach the Comm.
	if err := s.StartCoordinator(ctx); err != nil {
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

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	br := bufio.NewReader(cc)

	send := func(s string) { fmt.Fprintf(cc, "%s\r\n", s) }
	readUntilTag := func(tag string) []string {
		var lines []string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			line = strings.TrimRight(line, "\r\n")
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				return lines
			}
		}
	}

	_ = readUntilTag("*")            // greeting (untagged * OK)
	send("a login u1@example.com x") // login
	readUntilTag("a")
	send("b select INBOX")
	readUntilTag("b")
	send("c notify set (selected (MessageNew MessageExpunge FlagChange))")
	readUntilTag("c")

	// Deliver a new message via the kernel (another path). NOTIFY must push EXISTS
	// unsolicited — read raw lines until we see it.
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: pushed\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}

	sawExists := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read waiting for EXISTS: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "* ") && strings.HasSuffix(line, "EXISTS") {
			// e.g. "* 2 EXISTS"
			sawExists = true
			break
		}
	}
	if !sawExists {
		t.Fatalf("did not receive unsolicited EXISTS after NOTIFY SET + delivery")
	}

	// NOTIFY NONE disables further pushes.
	send("d notify none")
	readUntilTag("d")

	t.Logf("OK: NOTIFY SET pushed unsolicited EXISTS on delivery (not in IDLE); NOTIFY NONE accepted")
}
