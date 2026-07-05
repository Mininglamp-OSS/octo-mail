package imapd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestMailboxLifecycle drives the full IMAP mailbox/message-management surface
// added in WF4 with an unmodified imapclient: CREATE a mailbox, APPEND a
// message into it, SELECT it, COPY then MOVE to another mailbox, then flag
// \Deleted + EXPUNGE, and finally DELETE the mailbox. Each step is verified via
// the protocol (EXISTS counts, search results) — not by peeking at the DB.
func TestMailboxLifecycle(t *testing.T) {
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

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatalf("login: %v", err)
	}

	// CREATE Drafts.
	if _, err := ic.Create("Drafts", nil); err != nil {
		t.Fatalf("CREATE Drafts: %v", err)
	}
	// APPEND a message to Drafts.
	msg := "From: u1@example.com\r\nTo: u1@example.com\r\nSubject: draft one\r\n\r\nhello draft\r\n"
	if _, err := ic.Append("Drafts", imapclient.Append{Flags: []string{`\Draft`}, Size: int64(len(msg)), Data: strings.NewReader(msg)}); err != nil {
		t.Fatalf("APPEND: %v", err)
	}
	// SELECT Drafts -> 1 EXISTS.
	sel, err := ic.Select("Drafts")
	if err != nil {
		t.Fatalf("SELECT Drafts: %v", err)
	}
	if !hasExists(sel, 1) {
		t.Fatalf("Drafts EXISTS != 1 after APPEND: %+v", sel.Untagged)
	}

	// CREATE Archive; COPY uid 1 there; verify Archive has 1.
	if _, err := ic.Create("Archive", nil); err != nil {
		t.Fatalf("CREATE Archive: %v", err)
	}
	if _, err := ic.UIDCopy("1", "Archive"); err != nil {
		t.Fatalf("UID COPY: %v", err)
	}
	selA, err := ic.Select("Archive")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExists(selA, 1) {
		t.Fatalf("Archive EXISTS != 1 after COPY: %+v", selA.Untagged)
	}

	// Back to Drafts; MOVE uid 1 to a new folder "Sent".
	if _, err := ic.Select("Drafts"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.UIDMove("1", "Sent"); err != nil {
		t.Fatalf("UID MOVE: %v", err)
	}
	// Drafts should now be empty.
	selD, err := ic.Select("Drafts")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExists(selD, 0) {
		t.Fatalf("Drafts EXISTS != 0 after MOVE: %+v", selD.Untagged)
	}
	// Sent should have the message.
	selS, err := ic.Select("Sent")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExists(selS, 1) {
		t.Fatalf("Sent EXISTS != 1 after MOVE: %+v", selS.Untagged)
	}

	// Flag \Deleted and EXPUNGE in Sent -> empty.
	if err := ic.WriteCommandf("", "uid store 1 +FLAGS (\\Deleted)"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Expunge(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}
	selS2, err := ic.Select("Sent")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExists(selS2, 0) {
		t.Fatalf("Sent EXISTS != 0 after EXPUNGE: %+v", selS2.Untagged)
	}

	// DELETE the now-empty Archive mailbox.
	if _, err := ic.Delete("Archive"); err != nil {
		t.Fatalf("DELETE Archive: %v", err)
	}
	t.Logf("OK: CREATE/APPEND/SELECT/COPY/MOVE/STORE+EXPUNGE/DELETE all drove through real imapclient")
}
