package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestResyncRecoversMissedNotifications proves the H6 fix (#8): after a LISTEN
// outage, replaying subscribers from their last-seen offset recovers changes
// whose NOTIFY was missed. Node B registers a subscriber but does NOT run its
// coordinator (simulating the dropped LISTEN connection), so node A's delivery
// notification never reaches it live; resyncAll (what the reconnect supervisor
// calls) then delivers the missed change.
func TestResyncRecoversMissedNotifications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	open := func(truncate bool, coord bool) *postgres.Store {
		bs, _ := blob.NewFS(t.TempDir())
		s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
		if err != nil {
			t.Skipf("postgres not available (%v)", err)
		}
		if truncate {
			s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`)
		}
		if coord {
			if err := s.StartCoordinator(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(s.Close)
		return s
	}
	// Node A runs its coordinator (emits notifies); node B does NOT (its LISTEN is
	// "down"), so it will miss the live notification.
	a := open(true, true)
	b := open(false, false)

	var tenantID, accID, domID int64
	a.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	a.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	a.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	a.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)

	accB := b.OpenAccountForTest(accID, tenantID, "u1")
	comm := accB.RegisterComm()
	defer comm.Close()

	// Deliver on node A. Node B's coordinator is down, so no live change arrives.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := a.NewDirectory().ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: y\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	// Confirm B did NOT receive it live (its LISTEN is down).
	select {
	case <-comm.Changes:
		t.Fatal("node B received a live change despite its coordinator being down")
	case <-time.After(500 * time.Millisecond):
	}

	// Simulate reconnect recovery: resyncAll replays subscribers from last-seen.
	b.ResyncAllForTest(ctx)

	select {
	case changes := <-comm.Changes:
		if len(changes) == 0 {
			t.Fatal("resync delivered an empty batch")
		}
		t.Logf("OK: resync recovered %d missed change(s) after a LISTEN outage", len(changes))
	case <-time.After(8 * time.Second):
		t.Fatal("resync did not recover the missed change")
	}
}
