package postgres

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// The coordinator makes change-notification cross-node via Postgres LISTEN/NOTIFY
// on a single channel. It is a doorbell, not a bus: the payload is just
// "<accountID>:<seq>", and a woken node replays the change-log (seq > lastSeen)
// to synthesize the []Change its local IMAP IDLE / JMAP push subscribers expect.
// The durable log is the real channel; a missed NOTIFY is caught by the next one
// or by client resync, because truth is the log offset, not the message.
//
// Mirrors Stalwart's pub/sub-only coordinator: no consensus, no locking —
// serialization is the per-account advisory lock in the write path.

const notifyChannel = "octo_mail_changelog"

// StartCoordinator launches the cross-node LISTEN loop on a dedicated pooled
// connection. Call once per node after Open. Runs until ctx is cancelled.
func (s *Store) StartCoordinator(ctx context.Context) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		conn.Release()
		return err
	}
	s.coordEnabled.Store(true)
	go s.listenLoop(ctx, conn)
	return nil
}

func (s *Store) listenLoop(ctx context.Context, conn *pgxpool.Conn) {
	defer conn.Release()
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return // ctx cancelled or connection lost; node resyncs on reconnect
		}
		accID, seq, ok := parseNotify(n.Payload)
		if !ok {
			continue
		}
		s.onRemoteChange(ctx, accID, seq)
	}
}

// onRemoteChange fans a cross-node notification to local subscribers by
// replaying the log past what each has seen. Same-node writes were already
// delivered rich in-process (see publish), and their lastSeq is advanced there,
// so this path is a no-op for them and only serves OTHER nodes' writes.
func (s *Store) onRemoteChange(ctx context.Context, accID int64, seq store.ModSeq) {
	s.mu.Lock()
	subs := append([]*subscriber(nil), s.subs[accID]...)
	s.mu.Unlock()

	for _, sub := range subs {
		if sub.seen() >= seq {
			continue
		}
		changes, head, err := s.ReplayChanges(ctx, accID, sub.seen())
		if err != nil || len(changes) == 0 {
			continue
		}
		select {
		case sub.comm.Changes <- changes:
			sub.advance(head)
		default:
		}
	}
}

// emitNotify rings the doorbell after a committed write.
func (s *Store) emitNotify(ctx context.Context, accountID, seq int64) {
	if !s.coordEnabled.Load() {
		return
	}
	_, _ = s.Pool.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel,
		strconv.FormatInt(accountID, 10)+":"+strconv.FormatInt(seq, 10))
}

func parseNotify(payload string) (accID int64, seq store.ModSeq, ok bool) {
	a, b, found := strings.Cut(payload, ":")
	if !found {
		return 0, 0, false
	}
	ai, err1 := strconv.ParseInt(a, 10, 64)
	si, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return ai, store.ModSeq(si), true
}
