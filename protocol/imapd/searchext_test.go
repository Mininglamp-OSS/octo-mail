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

// TestSearchExtensions drives the IMAP search & mailbox long-tail with the
// unmodified imapclient: ESEARCH (RETURN MIN/MAX/COUNT/ALL), SEARCHRES ($ saved
// result), WITHIN (OLDER/YOUNGER), STATUS=SIZE, MULTIAPPEND, and ID.
func TestSearchExtensions(t *testing.T) {
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

	// Deliver 3 messages to Inbox.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		raw := fmt.Sprintf("From: s%d@remote.example\r\nSubject: msg%d\r\n\r\nbody %d\r\n", i, i, i)
		if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
			t.Fatal(err)
		}
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(30 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatalf("login: %v", err)
	}

	// ID (RFC 2971).
	if err := ic.WriteCommandf("", `id ("name" "testclient")`); err != nil {
		t.Fatal(err)
	}
	idResp, err := ic.ReadResponse()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	sawID := false
	for _, u := range idResp.Untagged {
		if _, ok := u.(imapclient.UntaggedID); ok {
			sawID = true
		}
	}
	if !sawID {
		t.Fatalf("ID returned no untagged ID response")
	}

	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	// Helper: run a raw command and collect the first ESEARCH response.
	esearch := func(cmd string) imapclient.UntaggedEsearch {
		if err := ic.WriteCommandf("", "%s", cmd); err != nil {
			t.Fatal(err)
		}
		resp, err := ic.ReadResponse()
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		for _, u := range resp.Untagged {
			if e, ok := u.(imapclient.UntaggedEsearch); ok {
				return e
			}
		}
		t.Fatalf("%s: no ESEARCH response (untagged=%+v)", cmd, resp.Untagged)
		return imapclient.UntaggedEsearch{}
	}

	// ESEARCH COUNT over ALL messages.
	e := esearch("uid search return (count) all")
	if e.Count == nil || *e.Count != 3 {
		t.Fatalf("ESEARCH COUNT = %v, want 3", e.Count)
	}

	// ESEARCH MIN/MAX over ALL.
	e = esearch("uid search return (min max) all")
	if e.Min != 1 || e.Max != 3 {
		t.Fatalf("ESEARCH MIN/MAX = %d/%d, want 1/3", e.Min, e.Max)
	}

	// ESEARCH ALL with a subject filter → uid 2 only.
	e = esearch("uid search return (all) subject msg1")
	if got := numsetString(e.All); got != "2" {
		t.Fatalf("ESEARCH ALL subject msg1 = %q, want \"2\"", got)
	}

	// SEARCHRES: SAVE the msg1 result, then reference it with $.
	if err := ic.WriteCommandf("", "uid search return (save) subject msg1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.ReadResponse(); err != nil {
		t.Fatalf("SEARCH SAVE: %v", err)
	}
	e = esearch("uid search return (all) $")
	if got := numsetString(e.All); got != "2" {
		t.Fatalf("ESEARCH $ = %q, want \"2\" (saved result)", got)
	}

	// WITHIN: all 3 messages were just delivered, so YOUNGER 3600 matches all,
	// OLDER 3600 matches none.
	e = esearch("uid search return (count) younger 3600")
	if e.Count == nil || *e.Count != 3 {
		t.Fatalf("ESEARCH YOUNGER 3600 COUNT = %v, want 3", e.Count)
	}
	e = esearch("uid search return (count) older 3600")
	if e.Count == nil || *e.Count != 0 {
		t.Fatalf("ESEARCH OLDER 3600 COUNT = %v, want 0", e.Count)
	}

	// STATUS=SIZE: report the total octet size of INBOX.
	stResp, err := ic.Status("INBOX", imapclient.StatusMessages, imapclient.StatusSize)
	if err != nil {
		t.Fatalf("STATUS SIZE: %v", err)
	}
	var st imapclient.UntaggedStatus
	for _, u := range stResp.Untagged {
		if x, ok := u.(imapclient.UntaggedStatus); ok {
			st = x
		}
	}
	if st.Attrs[imapclient.StatusMessages] != 3 {
		t.Fatalf("STATUS MESSAGES = %d, want 3", st.Attrs[imapclient.StatusMessages])
	}
	if st.Attrs[imapclient.StatusSize] <= 0 {
		t.Fatalf("STATUS SIZE = %d, want > 0", st.Attrs[imapclient.StatusSize])
	}

	// MULTIAPPEND: append two messages in one command.
	m1 := "Subject: multi1\r\n\r\nfirst\r\n"
	m2 := "Subject: multi2\r\n\r\nsecond\r\n"
	if _, err := ic.MultiAppend("INBOX",
		imapclient.Append{Size: int64(len(m1)), Data: strings.NewReader(m1)},
		imapclient.Append{Size: int64(len(m2)), Data: strings.NewReader(m2)},
	); err != nil {
		t.Fatalf("MULTIAPPEND: %v", err)
	}
	// INBOX now has 5 messages.
	stResp, err = ic.Status("INBOX", imapclient.StatusMessages)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range stResp.Untagged {
		if x, ok := u.(imapclient.UntaggedStatus); ok {
			if x.Attrs[imapclient.StatusMessages] != 5 {
				t.Fatalf("after MULTIAPPEND MESSAGES = %d, want 5", x.Attrs[imapclient.StatusMessages])
			}
		}
	}

	t.Logf("OK: ID, ESEARCH COUNT/MIN/MAX/ALL, SEARCHRES $, WITHIN OLDER/YOUNGER, STATUS SIZE, MULTIAPPEND (2 msgs) via real imapclient")
}

// numsetString renders an imapclient NumSet result set compactly (e.g. "2" or
// "1:3") for assertions.
func numsetString(ns imapclient.NumSet) string {
	var parts []string
	for _, r := range ns.Ranges {
		if r.Last == nil || *r.Last == r.First {
			parts = append(parts, fmt.Sprintf("%d", r.First))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", r.First, *r.Last))
		}
	}
	return strings.Join(parts, ",")
}
