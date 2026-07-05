package postgres_test

import (
	"context"
	"os"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

// TestHAFailoverPromoted verifies the second half of HA: after the replica is
// PROMOTED to primary (pg_promote), the octo-mail kernel pointed at the promoted node
// finds the pre-failover data intact AND can continue delivering — the new writes
// advance the changelog from the replayed offset, and the head==max(seq)
// invariant still holds. Run after the promotion step, with OCTO_MAIL_HA_FAILOVER=1
// and OCTO_MAIL_HA_PROMOTED pointing at the promoted node.
func TestHAFailoverPromoted(t *testing.T) {
	if os.Getenv("OCTO_MAIL_HA_FAILOVER") != "1" {
		t.Skip("failover test requires OCTO_MAIL_HA_FAILOVER=1 after promoting the replica")
	}
	ctx := context.Background()
	promotedDSN := haEnv("OCTO_MAIL_HA_PROMOTED", "postgres://octo_mail:octo_mail@localhost:55434/octo_mail")

	bs, _ := blob.NewFS(t.TempDir())
	// Open the kernel against the PROMOTED node (was the replica).
	s, err := postgres.Open(ctx, promotedDSN, bs)
	if err != nil {
		t.Skipf("promoted node not available (%v)", err)
	}
	defer s.Close()

	// The pre-failover delivery must have survived promotion.
	var accID, msgs, headBefore int64
	haMust(t, s.Pool.QueryRow(ctx, `SELECT id FROM accounts WHERE name='u1'`).Scan(&accID))
	haMust(t, s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, accID).Scan(&msgs))
	if msgs != 1 {
		t.Fatalf("promoted node has %d messages, want 1 (data lost across failover)", msgs)
	}
	haMust(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&headBefore))

	// The promoted node accepts writes: continue delivering through the kernel.
	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memBytes("Subject: after-failover\r\n\r\nnew write post promotion\r\n")); err != nil {
		t.Fatalf("delivery to promoted node failed: %v", err)
	}

	var headAfter, msgsAfter, maxSeq int64
	haMust(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&headAfter))
	haMust(t, s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, accID).Scan(&msgsAfter))
	haMust(t, s.Pool.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, accID).Scan(&maxSeq))

	if msgsAfter != 2 {
		t.Fatalf("after post-failover delivery: %d messages, want 2", msgsAfter)
	}
	if headAfter <= headBefore {
		t.Fatalf("changelog did not advance on promoted node: before=%d after=%d", headBefore, headAfter)
	}
	if headAfter != maxSeq {
		t.Fatalf("changelog invariant broken on promoted node: head=%d max=%d", headAfter, maxSeq)
	}
	t.Logf("OK: failover survived — pre-failover msg intact, promoted node accepted new delivery (head %d→%d, 2 msgs, invariant holds)", headBefore, headAfter)
}
