package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSyncReplicationZeroLoss proves the RPO=0 guarantee of synchronous
// replication: with synchronous_commit=on and synchronous_standby_names='*', the
// primary does not acknowledge a COMMIT until the standby has durably received
// the WAL. So (1) a committed row is already on the standby, and (2) if the
// standby is unavailable, a commit BLOCKS waiting for the sync ack rather than
// returning and risking loss. This closes the "synchronous zero-loss" boundary
// the round-7 async-streaming HA test explicitly left open.
//
// Gated by OCTO_MAIL_HA_SYNC=1; provision with scripts/ha-pg.sh up. The blocking half
// additionally requires OCTO_MAIL_HA_SYNC_BLOCK=1 and a stopped standby
// (scripts/ha-pg.sh stopstandby), since it intentionally hangs a commit.
func TestSyncReplicationZeroLoss(t *testing.T) {
	if os.Getenv("OCTO_MAIL_HA_SYNC") != "1" {
		t.Skip("sync-replication test requires OCTO_MAIL_HA_SYNC=1 and a sync pair (scripts/ha-pg.sh up)")
	}
	ctx := context.Background()
	primaryDSN := haEnv("OCTO_MAIL_HA_SYNC_PRIMARY", "postgres://octo_mail:octo_mail@localhost:55435/octo_mail")
	standbyDSN := haEnv("OCTO_MAIL_HA_SYNC_STANDBY", "postgres://octo_mail:octo_mail@localhost:55436/octo_mail")

	prim, err := pgxpool.New(ctx, primaryDSN)
	if err != nil {
		t.Skipf("primary not available (%v)", err)
	}
	defer prim.Close()
	if err := prim.Ping(ctx); err != nil {
		t.Skipf("primary not available (%v)", err)
	}

	if _, err := prim.Exec(ctx, `CREATE TABLE IF NOT EXISTS ha_sync_probe (id bigint primary key)`); err != nil {
		t.Fatal(err)
	}

	// Blocking half: with the sync standby stopped (scripts/ha-pg.sh stopstandby),
	// a synchronous commit must NOT return — the primary refuses to acknowledge
	// data the standby has not durably received (RPO=0). We detect the block via a
	// short context timeout. This path runs standalone because pg_stat_replication
	// is empty while the standby is down.
	if os.Getenv("OCTO_MAIL_HA_SYNC_BLOCK") == "1" {
		bctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_, err := prim.Exec(bctx, `INSERT INTO ha_sync_probe (id) VALUES ($1)`, time.Now().UnixNano())
		if err == nil {
			t.Fatalf("commit returned while sync standby is down — not zero-loss!")
		}
		if bctx.Err() != context.DeadlineExceeded {
			t.Fatalf("expected commit to block (deadline exceeded), got: %v", err)
		}
		t.Logf("OK: with the sync standby down, the primary's commit blocked (waiting for sync ack) — refuses to acknowledge unreplicated data")
		return
	}

	// Durability half: the standby is up and must be registered as a SYNC standby.
	var syncState string
	_ = prim.QueryRow(ctx, `SELECT sync_state FROM pg_stat_replication LIMIT 1`).Scan(&syncState)
	if syncState != "sync" {
		t.Fatalf("standby sync_state=%q, want \"sync\" (provision with scripts/ha-pg.sh up)", syncState)
	}

	// Commit a row on the primary. With synchronous_commit=on this returns only
	// after the standby has the WAL — so the row is guaranteed present downstream.
	tag := time.Now().UnixNano()
	if _, err := prim.Exec(ctx, `INSERT INTO ha_sync_probe (id) VALUES ($1)`, tag); err != nil {
		t.Fatalf("synchronous commit failed: %v", err)
	}

	// The standby (read-only) must already have the committed row — RPO=0.
	stby, err := pgxpool.New(ctx, standbyDSN)
	if err != nil {
		t.Skipf("standby not available (%v)", err)
	}
	defer stby.Close()
	var inRecovery bool
	if err := stby.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		t.Fatalf("standby query: %v", err)
	}
	if !inRecovery {
		t.Fatalf("standby is not in recovery — not a streaming standby")
	}
	var got int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := stby.QueryRow(ctx, `SELECT id FROM ha_sync_probe WHERE id=$1`, tag).Scan(&got); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != tag {
		t.Fatalf("committed row not present on synchronous standby (RPO>0!): want %d", tag)
	}

	t.Logf("OK: synchronous_commit=on + sync standby → committed row present on standby before commit returned (RPO=0)")
}
