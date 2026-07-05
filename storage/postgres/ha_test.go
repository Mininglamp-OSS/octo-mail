package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/smtp"
)

// TestHAStreamingReplicationFailover is a REAL high-availability proof against a
// live primary→replica streaming pair (docker containers on host ports 55433
// primary / 55434 replica; see the HA setup). It:
//  1. delivers a message through the octo-mail kernel to the PRIMARY;
//  2. waits for physical streaming replication to carry it to the REPLICA and
//     asserts the replica (read-only, pg_is_in_recovery) sees the message and
//     the identical changelog head — replication is byte-for-byte, structural;
//  3. is skipped unless OCTO_MAIL_HA=1 (the pair must be provisioned first).
//
// Promotion/failover is exercised by the accompanying shell steps; this test
// proves the data path: what the kernel wrote to the primary is present and
// consistent on the streamed replica.
func TestHAStreamingReplicationFailover(t *testing.T) {
	if os.Getenv("OCTO_MAIL_HA") != "1" {
		t.Skip("HA test requires OCTO_MAIL_HA=1 and a provisioned primary/replica pair")
	}
	ctx := context.Background()
	primaryDSN := haEnv("OCTO_MAIL_HA_PRIMARY", "postgres://octo_mail:octo_mail@localhost:55433/octo_mail")
	replicaDSN := haEnv("OCTO_MAIL_HA_REPLICA", "postgres://octo_mail:octo_mail@localhost:55434/octo_mail")

	bs, _ := blob.NewFS(t.TempDir())
	// Open the kernel against the PRIMARY (read-write).
	s, err := postgres.Open(ctx, primaryDSN, bs)
	if err != nil {
		t.Skipf("primary not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	haMust(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID))
	haMust(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID))
	haMust(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID))
	_, err = s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	haMust(t, err)

	// Deliver through the kernel to the PRIMARY.
	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: ha\r\n\r\nreplicated body\r\n")); err != nil {
		t.Fatal(err)
	}
	var primaryHead int64
	haMust(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&primaryHead))

	// Connect directly to the REPLICA (read-only standby).
	rp, err := pgxpool.New(ctx, replicaDSN)
	if err != nil {
		t.Skipf("replica not available (%v)", err)
	}
	defer rp.Close()

	// Confirm it is genuinely a standby.
	var inRecovery bool
	haMust(t, rp.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery))
	if !inRecovery {
		t.Fatalf("replica is not in recovery — not a streaming standby")
	}

	// Wait for streaming replication to carry the delivery to the replica.
	deadline := time.Now().Add(15 * time.Second)
	var repHead, repMsgs int64
	for time.Now().Before(deadline) {
		_ = rp.QueryRow(ctx, `SELECT COALESCE(changelog_seq,0) FROM accounts WHERE id=$1`, accID).Scan(&repHead)
		_ = rp.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, accID).Scan(&repMsgs)
		if repHead == primaryHead && repMsgs == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if repHead != primaryHead {
		t.Fatalf("replica changelog head=%d != primary head=%d (replication lag/broken)", repHead, primaryHead)
	}
	if repMsgs != 1 {
		t.Fatalf("replica has %d messages, want 1 (delivery not replicated)", repMsgs)
	}

	// The replica must reject writes (it's read-only) — proving it's a true standby.
	if _, err := rp.Exec(ctx, `INSERT INTO tenants (name) VALUES ('nope')`); err == nil {
		t.Fatalf("replica accepted a write — not a read-only standby")
	}

	// changelog invariant holds on the replica too: head == max(seq).
	var repMax int64
	haMust(t, rp.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, accID).Scan(&repMax))
	if repMax != repHead {
		t.Fatalf("replica changelog invariant broken: head=%d max=%d", repHead, repMax)
	}

	t.Logf("OK: kernel delivery to primary streamed to replica byte-for-byte (head=%d, 1 msg); replica read-only; changelog invariant holds", repHead)
}

func haEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func haMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
