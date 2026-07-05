package postgres_test

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestShardingTransparentAndDistributed proves P4: the change-log is
// hash-partitioned by account_id, and this is transparent (all other tests pass
// unchanged) AND real (rows for different accounts land in different partitions,
// and account-scoped reads prune to a single partition).
func TestShardingTransparentAndDistributed(t *testing.T) {
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

	// Confirm changelog is actually partitioned.
	var partkey string
	err = s.Pool.QueryRow(ctx, `
		SELECT pg_get_partkeydef('changelog'::regclass)`).Scan(&partkey)
	if err != nil {
		t.Fatalf("changelog is not partitioned: %v", err)
	}
	t.Logf("changelog partition key: %s", partkey)

	// Create several accounts and deliver to each, so changelog rows spread.
	var tenantID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)

	const nAccounts = 12
	var accIDs []int64
	dir := s.NewDirectory()
	for i := 0; i < nAccounts; i++ {
		name := "u" + itoaSh(i)
		var accID int64
		s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,$2) RETURNING id`, tenantID, name).Scan(&accID)
		s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,$4)`, tenantID, domID, accID, name)
		accIDs = append(accIDs, accID)

		target, err := dir.ResolveInbound(ctx, mustAddrSh(t, name+"@example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: x\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	// Prove rows landed in MORE THAN ONE physical partition.
	rows, err := s.Pool.Query(ctx, `
		SELECT tableoid::regclass::text AS partition, count(*)
		FROM changelog GROUP BY 1 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	partitions := map[string]int64{}
	for rows.Next() {
		var part string
		var cnt int64
		if err := rows.Scan(&part, &cnt); err != nil {
			t.Fatal(err)
		}
		partitions[part] = cnt
	}
	if len(partitions) < 2 {
		t.Fatalf("changelog rows landed in only %d partition(s); expected spread across multiple: %v", len(partitions), partitions)
	}
	t.Logf("changelog rows distributed across %d partitions: %v", len(partitions), partitions)

	// Prove partition pruning: an account-scoped query touches exactly ONE
	// partition, not all four. Count DISTINCT partitions named in the plan.
	planRows, err := s.Pool.Query(ctx, `EXPLAIN SELECT * FROM changelog WHERE account_id=$1`, accIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer planRows.Close()
	touched := map[string]bool{}
	var planText string
	for planRows.Next() {
		var line string
		planRows.Scan(&line)
		planText += line + "\n"
		for p := 0; p < 4; p++ {
			name := "changelog_p" + itoaSh(p)
			if containsAny(line, name) {
				touched[name] = true
			}
		}
	}
	if len(touched) == 0 {
		t.Fatalf("plan referenced no partition; sharding not effective:\n%s", planText)
	}
	if len(touched) > 1 {
		t.Fatalf("account-scoped query touched %d partitions (no pruning): %v\n%s", len(touched), touched, planText)
	}
	t.Logf("OK: account-scoped changelog query pruned to a single partition; sharding transparent + distributed")
}

// --- small local helpers (avoid clashing with other test files) ---

func itoaSh(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func mustAddrSh(t *testing.T, a string) smtp.Path {
	t.Helper()
	addr, err := smtp.ParseAddress(a)
	if err != nil {
		t.Fatal(err)
	}
	return addr.Path()
}

func containsAny(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
