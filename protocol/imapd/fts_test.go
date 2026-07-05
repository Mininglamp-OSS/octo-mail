package imapd_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestFTSProjectionAndRebuild proves the async projection model end to end:
//  1. FTS is a tolerant async projection — before the worker runs, SEARCH TEXT
//     finds nothing (delivery does not synchronously index).
//  2. After the worker drains the log, a real IMAP UID SEARCH TEXT returns
//     exactly the matching message.
//  3. Rebuild-from-zero (drop projection + reset cursor + re-fold the whole log)
//     reproduces the identical result — the projection is a pure fold of the log.
func TestFTSProjectionAndRebuild(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, projection_cursor RESTART IDENTITY CASCADE`); err != nil {
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

	// Deliver two messages: only the first mentions "pineapple".
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: fruit\r\n\r\nI love pineapple pizza\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: veg\r\n\r\njust broccoli here\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	search := func(text string) []string {
		cc, sc := net.Pipe()
		go func() { _ = srv.Serve(ctx, sc) }()
		_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
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
		if err := ic.WriteCommandf("", "uid search text %s", text); err != nil {
			t.Fatal(err)
		}
		resp, err := ic.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		var uids []string
		for _, u := range resp.Untagged {
			if sr, ok := u.(imapclient.UntaggedSearch); ok {
				for _, n := range sr {
					uids = append(uids, strconv.FormatUint(uint64(n), 10))
				}
			}
		}
		return uids
	}

	// 1. Before the worker runs: async projection is empty, SEARCH finds nothing.
	if got := search("pineapple"); len(got) != 0 {
		t.Fatalf("SEARCH before indexing returned %v, want none (projection is async)", got)
	}

	// 2. Drain the FTS worker, then SEARCH finds exactly uid 1.
	w := &projection.FTSWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("fts drain: %v", err)
	}
	got := search("pineapple")
	if len(got) != 1 || got[0] != "1" {
		t.Fatalf("SEARCH TEXT pineapple = %v, want [1]", got)
	}
	if other := search("broccoli"); len(other) != 1 || other[0] != "2" {
		t.Fatalf("SEARCH TEXT broccoli = %v, want [2]", other)
	}

	// 3. Rebuild from zero reproduces the same result (pure fold of the log).
	var beforeCount int64
	mustScan(t, s, ctx, `SELECT count(*) FROM fts WHERE account_id=$1`, &beforeCount, accID)
	if err := w.RebuildAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	var afterCount int64
	mustScan(t, s, ctx, `SELECT count(*) FROM fts WHERE account_id=$1`, &afterCount, accID)
	if afterCount != beforeCount {
		t.Fatalf("rebuild produced %d fts rows, want %d (fold must be deterministic)", afterCount, beforeCount)
	}
	if got := search("pineapple"); len(got) != 1 || got[0] != "1" {
		t.Fatalf("SEARCH after rebuild = %v, want [1]", got)
	}
	t.Logf("OK: FTS async (empty pre-index) → drained → UID SEARCH TEXT hits; rebuild-from-zero reproduces identical result (%d rows)", afterCount)
}
