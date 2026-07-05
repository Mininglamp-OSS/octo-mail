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

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestIMAPDeliverAndFetch is the P1 crown-jewel proof: a message delivered into
// the change-log kernel is read back by the UNMODIFIED imapclient talking to
// our compact IMAP server over an in-memory pipe. Proves the reused protocol
// client and a kernel-bound server interoperate — mail flows log → IMAP.
func TestIMAPDeliverAndFetch(t *testing.T) {
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

	// Clean slate + seed one tenant/account/domain/address.
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
	if err := dir.SetPassword(ctx, "u1@example.com", "irrelevant"); err != nil {
		t.Fatal(err)
	}

	// Deliver a message via the inbound (directory) path — the "SMTP receive" side.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatalf("resolve inbound: %v", err)
	}
	const body = "From: alice@remote.example\r\nTo: u1@example.com\r\nSubject: hello\r\n\r\nthe body\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(body)); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	// Wire the IMAP server and the imapclient over an in-memory pipe.
	srv := &imapd.Server{Dir: dir}
	cliConn, srvConn := net.Pipe()
	go func() {
		_ = srv.Serve(ctx, srvConn)
	}()
	_ = cliConn.SetDeadline(time.Now().Add(60 * time.Second))

	cl, err := imapclient.New(cliConn, nil)
	if err != nil {
		t.Fatalf("imapclient new (greeting): %v", err)
	}
	defer cl.Close()

	if _, err := cl.Login("u1@example.com", "irrelevant"); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
	sel, err := cl.Select("INBOX")
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if !hasExists(sel, 1) {
		t.Fatalf("SELECT did not report 1 EXISTS: %+v", sel.Untagged)
	}

	// UID FETCH 1 (FLAGS BODY[]) — read the message back through the kernel.
	if err := cl.WriteCommandf("", "uid fetch 1 (FLAGS BODY[])"); err != nil {
		t.Fatalf("write fetch: %v", err)
	}
	resp, err := cl.ReadResponse()
	if err != nil {
		t.Fatalf("read fetch: %v", err)
	}
	gotBody, gotSeen := extractFetch(resp)
	if !strings.Contains(gotBody, "the body") {
		t.Fatalf("FETCH BODY[] missing content; got %q", gotBody)
	}
	if gotSeen {
		t.Fatalf("message should be unseen before STORE")
	}

	// UID STORE 1 +FLAGS (\Seen), then FETCH again to confirm it stuck.
	if _, err := cl.UIDStoreFlagsAdd("1", false, `\Seen`); err != nil {
		t.Fatalf("UID STORE: %v", err)
	}
	if err := cl.WriteCommandf("", "uid fetch 1 (FLAGS)"); err != nil {
		t.Fatal(err)
	}
	resp, err = cl.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if _, seen := extractFetch(resp); !seen {
		t.Fatalf("\\Seen not persisted after STORE")
	}

	// Invariant still holds after IMAP-driven mutations.
	var head, maxSeq int64
	mustScan(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head, accID)
	mustScan(t, s, ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, &maxSeq, accID)
	if head != maxSeq {
		t.Fatalf("modseq invariant broken after IMAP: head=%d max=%d", head, maxSeq)
	}
	t.Logf("OK: IMAP client fetched body via kernel; \\Seen persisted; head=maxseq=%d", head)
}

// --- helpers ---

func hasExists(r imapclient.Response, n uint32) bool {
	for _, u := range r.Untagged {
		if e, ok := u.(imapclient.UntaggedExists); ok && uint32(e) == n {
			return true
		}
	}
	return false
}

func extractFetch(r imapclient.Response) (body string, seen bool) {
	for _, u := range r.Untagged {
		f, ok := u.(imapclient.UntaggedFetch)
		if !ok {
			continue
		}
		for _, a := range f.Attrs {
			switch x := a.(type) {
			case imapclient.FetchBody:
				body = x.Body
			case imapclient.FetchFlags:
				for _, fl := range x {
					if fl == `\Seen` {
						seen = true
					}
				}
			}
		}
	}
	return body, seen
}
