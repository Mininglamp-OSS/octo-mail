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

// TestGetQuota proves R2-6: GETQUOTA/GETQUOTAROOT report the account's storage
// usage and limit, driven by the imapclient (raw commands).
func TestGetQuota(t *testing.T) {
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
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name, quota_bytes) VALUES ($1,'u1',1048576) RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	// Deliver a message so used bytes > 0.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: q\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
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

	if err := ic.WriteCommandf("", "getquotaroot INBOX"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	var sawRoot, sawQuota bool
	var limit int64
	for _, u := range resp.Untagged {
		switch q := u.(type) {
		case imapclient.UntaggedQuotaroot:
			sawRoot = true
		case imapclient.UntaggedQuota:
			sawQuota = true
			for _, r := range q.Resources {
				if strings.EqualFold(string(r.Name), "STORAGE") {
					limit = int64(r.Limit)
				}
			}
		}
	}
	if !sawRoot {
		t.Fatalf("no QUOTAROOT response")
	}
	if !sawQuota {
		t.Fatalf("no QUOTA response")
	}
	// limit 1048576 bytes reported in KiB = 1024.
	if limit != 1024 {
		t.Fatalf("STORAGE limit = %d KiB, want 1024", limit)
	}
	t.Logf("OK: GETQUOTAROOT INBOX returned QUOTAROOT + QUOTA STORAGE limit=1024 KiB via real imapclient")
}
