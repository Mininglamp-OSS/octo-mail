package imapd_test

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestSearchCriteriaTree proves R2-1 (SEARCH condition tree) + R2-3 (real
// INTERNALDATE via SINCE): deliver messages with distinct From/Subject/flags and
// exercise FROM, SUBJECT, SEEN/UNSEEN, NOT, OR, LARGER, SINCE via an
// unmodified imapclient, asserting the returned UID sets are correct.
func TestSearchCriteriaTree(t *testing.T) {
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
	// uid1: from alice, subject "invoice", small
	// uid2: from bob,   subject "lunch",   large
	// uid3: from alice, subject "report",  small
	deliver := func(from, subj, extra string) {
		raw := "From: " + from + "\r\nTo: u1@example.com\r\nSubject: " + subj + "\r\n\r\n" + extra + "\r\n"
		if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	deliver("alice@remote.example", "invoice", "short")
	deliver("bob@remote.example", "lunch", "this is a much larger body "+string(make([]byte, 2000)))
	deliver("alice@remote.example", "report", "short")

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
		t.Fatal(err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}
	// Mark uid1 \Seen.
	ic.WriteCommandf("", "uid store 1 +FLAGS (\\Seen)")
	ic.ReadResponse()

	search := func(crit string) []uint32 {
		if err := ic.WriteCommandf("", "uid search %s", crit); err != nil {
			t.Fatal(err)
		}
		resp, err := ic.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		var out []uint32
		for _, u := range resp.Untagged {
			if sr, ok := u.(imapclient.UntaggedSearch); ok {
				out = append(out, sr...)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	eq := func(name string, got []uint32, want ...uint32) {
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %v, want %v", name, got, want)
			}
		}
	}

	eq("FROM alice", search(`FROM alice@remote.example`), 1, 3)
	eq("SUBJECT invoice", search(`SUBJECT invoice`), 1)
	eq("SEEN", search(`SEEN`), 1)
	eq("UNSEEN", search(`UNSEEN`), 2, 3)
	eq("FROM alice UNSEEN", search(`FROM alice@remote.example UNSEEN`), 3)
	eq("NOT FROM alice", search(`NOT FROM alice@remote.example`), 2)
	eq("OR SUBJECT invoice SUBJECT lunch", search(`OR SUBJECT invoice SUBJECT lunch`), 1, 2)
	eq("LARGER 1000", search(`LARGER 1000`), 2)
	eq("SMALLER 1000", search(`SMALLER 1000`), 1, 3)
	// SINCE today (all messages were just delivered) → all 3.
	today := time.Now().UTC().Format("02-Jan-2006")
	eq("SINCE today", search(`SINCE `+today), 1, 2, 3)
	// BEFORE today → none (all received today).
	eq("BEFORE today", search(`BEFORE `+today))

	t.Logf("OK: SEARCH FROM/SUBJECT/SEEN/UNSEEN/AND/NOT/OR/LARGER/SMALLER/SINCE/BEFORE all correct via real imapclient")
}
