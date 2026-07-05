package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/smtp"
)

// TestQuotaEnforced proves quota is not merely tracked but ENFORCED: once an
// account's byte quota is reached, further delivery is rejected with
// store.ErrOverQuota and the changelog does not advance for the rejected
// message. Before WF3, CanAddMessageSize existed but no path consulted it, so
// delivery over quota silently succeeded.
func TestQuotaEnforced(t *testing.T) {
	ctx := context.Background()
	s, dir, accID := setupTest(t)

	// Give the account a tight quota: 2000 bytes.
	if _, err := s.Pool.Exec(ctx, `UPDATE accounts SET quota_bytes=2000 WHERE id=$1`, accID); err != nil {
		t.Fatal(err)
	}

	addr, err := smtp.ParseAddress("u1@example.com")
	if err != nil {
		t.Fatal(err)
	}
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}

	body := func(n int) store.BlobReader {
		return memReader("Subject: x\r\n\r\n" + strings.Repeat("a", n) + "\r\n")
	}

	// First delivery (~1200 bytes) fits.
	if _, err := target.Deliver(ctx, &store.Message{}, body(1200)); err != nil {
		t.Fatalf("first delivery within quota failed: %v", err)
	}
	var headAfterFirst int64
	must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&headAfterFirst))

	// Second delivery (~1200 bytes) would exceed 2000: must be rejected.
	_, err = target.Deliver(ctx, &store.Message{}, body(1200))
	if err == nil {
		t.Fatalf("delivery over quota was accepted — quota not enforced")
	}
	if !errors.Is(err, store.ErrOverQuota) {
		t.Fatalf("expected ErrOverQuota, got %v", err)
	}

	// The rejected delivery must not have advanced the log or left a message.
	var headAfterReject, msgCount int64
	must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&headAfterReject))
	must(t, s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND NOT expunged`, accID).Scan(&msgCount))
	if headAfterReject != headAfterFirst {
		t.Fatalf("rejected delivery advanced changelog: %d -> %d", headAfterFirst, headAfterReject)
	}
	if msgCount != 1 {
		t.Fatalf("expected 1 stored message after over-quota reject, got %d", msgCount)
	}
	t.Logf("OK: over-quota delivery rejected with ErrOverQuota; changelog unchanged, no phantom message")
}
