package postgres_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestMessagesMailboxesSharded proves the WF5 deepening: messages AND mailboxes
// are now hash-partitioned by account_id too (P4 only sharded the changelog
// spine). It confirms — transparently (all other tests unchanged) — that rows
// for different accounts land in different physical partitions and that an
// account-scoped query prunes to a single partition. The composite PKs
// (account_id,id) and composite messages→mailboxes FK make this work with zero
// kernel/protocol changes.
func TestMessagesMailboxesSharded(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	// messages and mailboxes must be partitioned.
	for _, tbl := range []string{"messages", "mailboxes"} {
		var partkey string
		if err := s.Pool.QueryRow(ctx, `SELECT pg_get_partkeydef($1::regclass)`, tbl).Scan(&partkey); err != nil {
			t.Fatalf("%s is not partitioned: %v", tbl, err)
		}
		t.Logf("%s partition key: %s", tbl, partkey)
	}

	var tenantID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)

	dir := s.NewDirectory()
	const nAccounts = 12
	var accIDs []int64
	for i := 0; i < nAccounts; i++ {
		name := "u" + itoaSh(i)
		var accID int64
		s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,$2) RETURNING id`, tenantID, name).Scan(&accID)
		s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,$4)`, tenantID, domID, accID, name)
		accIDs = append(accIDs, accID)
		addr, _ := smtp.ParseAddress(name + "@example.com")
		target, err := dir.ResolveInbound(ctx, addr.Path())
		if err != nil {
			t.Fatal(err)
		}
		// Each delivery creates the Inbox mailbox and one message for this account.
		if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: x\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	// Both tables must spread across more than one physical partition.
	for _, tbl := range []string{"messages", "mailboxes"} {
		rows, err := s.Pool.Query(ctx, `SELECT tableoid::regclass::text, count(*) FROM `+tbl+` GROUP BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		parts := map[string]int64{}
		for rows.Next() {
			var p string
			var c int64
			rows.Scan(&p, &c)
			parts[p] = c
		}
		rows.Close()
		if len(parts) < 2 {
			t.Fatalf("%s rows in only %d partition(s), expected spread: %v", tbl, len(parts), parts)
		}
		t.Logf("%s distributed across %d partitions: %v", tbl, len(parts), parts)
	}

	// Partition pruning: an account-scoped messages query touches exactly one.
	planRows, err := s.Pool.Query(ctx, `EXPLAIN SELECT * FROM messages WHERE account_id=$1`, accIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer planRows.Close()
	touched := map[string]bool{}
	var plan string
	for planRows.Next() {
		var line string
		planRows.Scan(&line)
		plan += line + "\n"
		for p := 0; p < 4; p++ {
			if containsAny(line, "messages_p"+itoaSh(p)) {
				touched["messages_p"+itoaSh(p)] = true
			}
		}
	}
	if len(touched) != 1 {
		t.Fatalf("account-scoped messages query touched %d partitions (want 1):\n%s", len(touched), plan)
	}
	t.Logf("OK: messages+mailboxes sharded by account_id; account-scoped query pruned to one partition (transparent, kernel unchanged)")
}
