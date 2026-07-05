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

// TestSaveDateAndMultiSearch drives SAVEDATE (RFC 8514) via the real imapclient
// (FETCH SAVEDATE is modeled by the parser) and MULTISEARCH (RFC 7377, ESEARCH
// IN) via a raw client, since imapclient has no method to issue ESEARCH IN.
func TestSaveDateAndMultiSearch(t *testing.T) {
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
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("From: a@remote.example\r\nSubject: inboxmsg\r\n\r\nbody\r\n")); err != nil {
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

	// --- Part 1: SAVEDATE via the real imapclient. ---
	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	_ = conn1.SetDeadline(time.Now().Add(30 * time.Second))
	ic, err := imapclient.New(conn1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("select: %v", err)
	}
	// APPEND a message with a backdated INTERNALDATE: SAVEDATE (now) must differ
	// from INTERNALDATE (2000), proving they are distinct timestamps.
	msg := "Subject: appended\r\n\r\nhi\r\n"
	backdate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := ic.Append("INBOX", imapclient.Append{Received: &backdate, Size: int64(len(msg)), Data: strings.NewReader(msg)}); err != nil {
		t.Fatalf("append: %v", err)
	}

	if err := ic.WriteCommandf("", "uid fetch 2 (INTERNALDATE SAVEDATE)"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatalf("fetch savedate: %v", err)
	}
	var internal, saved *time.Time
	for _, u := range resp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				switch v := a.(type) {
				case imapclient.FetchInternalDate:
					internal = &v.Date
				case imapclient.FetchSaveDate:
					saved = v.SaveDate
				}
			}
		}
	}
	if internal == nil || saved == nil {
		t.Fatalf("missing INTERNALDATE (%v) or SAVEDATE (%v)", internal, saved)
	}
	if internal.Year() != 2000 {
		t.Fatalf("INTERNALDATE year = %d, want 2000 (backdated APPEND)", internal.Year())
	}
	if saved.Year() < 2020 {
		t.Fatalf("SAVEDATE year = %d, want current (save time, not backdated)", saved.Year())
	}

	// SEARCH SAVEDSINCE (a past date) matches both messages; SAVEDBEFORE (past)
	// matches none.
	un := searchUIDs(t, ic, "uid search savedsince 01-Jan-2020")
	if len(un) != 2 {
		t.Fatalf("SAVEDSINCE 2020 = %v, want 2 messages", un)
	}
	un = searchUIDs(t, ic, "uid search savedbefore 01-Jan-2020")
	if len(un) != 0 {
		t.Fatalf("SAVEDBEFORE 2020 = %v, want none", un)
	}

	// --- Part 2: MULTISEARCH (ESEARCH IN) via the raw client. ---
	// Create a second mailbox with a message so the multi-mailbox search returns
	// results attributed to each mailbox.
	if _, err := ic.Create("Work", nil); err != nil {
		t.Fatalf("create Work: %v", err)
	}
	wmsg := "Subject: workmsg\r\n\r\nwork\r\n"
	if _, err := ic.Append("Work", imapclient.Append{Size: int64(len(wmsg)), Data: strings.NewReader(wmsg)}); err != nil {
		t.Fatalf("append Work: %v", err)
	}

	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, conn2)
	rc.mustOK("b1", "login u1@example.com x")

	// ESEARCH IN (inboxes) RETURN (COUNT) ALL — search all mailboxes without
	// selecting; expect one ESEARCH line per non-empty mailbox with correlators.
	un2 := rc.mustOK("b2", "esearch in (inboxes) return (count) all")
	var inboxLine, workLine string
	for _, l := range un2 {
		if !strings.HasPrefix(l, "* ESEARCH") {
			continue
		}
		if strings.Contains(l, `MAILBOX "Inbox"`) {
			inboxLine = l
		}
		if strings.Contains(l, `MAILBOX "Work"`) {
			workLine = l
		}
	}
	if inboxLine == "" || workLine == "" {
		t.Fatalf("ESEARCH IN missing per-mailbox lines: %v", un2)
	}
	if !strings.Contains(inboxLine, "UIDVALIDITY") {
		t.Fatalf("ESEARCH Inbox line missing UIDVALIDITY correlator: %q", inboxLine)
	}
	if !strings.Contains(inboxLine, "COUNT 2") {
		t.Fatalf("ESEARCH Inbox COUNT = %q, want COUNT 2", inboxLine)
	}
	if !strings.Contains(workLine, "COUNT 1") {
		t.Fatalf("ESEARCH Work COUNT = %q, want COUNT 1", workLine)
	}

	// ESEARCH IN a single named mailbox with a subject filter.
	un2 = rc.mustOK("b3", `esearch in ("Work") return (all) subject workmsg`)
	found := false
	for _, l := range un2 {
		if strings.HasPrefix(l, "* ESEARCH") && strings.Contains(l, `MAILBOX "Work"`) && strings.Contains(l, "ALL 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ESEARCH IN (Work) subject filter did not return uid 1: %v", un2)
	}

	t.Logf("OK: SAVEDATE distinct from backdated INTERNALDATE, SAVEDSINCE/SAVEDBEFORE search, MULTISEARCH ESEARCH IN with per-mailbox MAILBOX/UIDVALIDITY correlators")
}

// searchUIDs runs a raw "uid search ..." via the imapclient and returns matched
// UIDs from the UntaggedSearch response.
func searchUIDs(t *testing.T, ic *imapclient.Conn, cmd string) []uint32 {
	if err := ic.WriteCommandf("", "%s", cmd); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	var out []uint32
	for _, u := range resp.Untagged {
		if sr, ok := u.(imapclient.UntaggedSearch); ok {
			out = append(out, sr...)
		}
	}
	return out
}
