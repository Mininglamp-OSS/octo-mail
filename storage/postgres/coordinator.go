package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

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
// connection. Call once per node after Open. Runs until ctx is cancelled,
// reconnecting (with backoff) across transient connection loss / PG restart /
// failover so cross-node push is not permanently lost after a blip.
//
// This connection is held for the node's whole lifetime (never returned to the
// pool while running), a permanent one-connection cost per node on top of any held
// leaderships — see the pool-sizing note on ops/ha.Leader and the DSN
// `pool_max_conns` knob in Open.
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
	go s.superviseListen(ctx, conn)
	return nil
}

// superviseListen runs listenLoop and, on any non-cancellation failure,
// re-establishes the LISTEN on a fresh connection and forces a resync of local
// subscribers (notifications during the outage were missed; truth is the log
// offset, so replaying from each subscriber's last-seen catches them up).
func (s *Store) superviseListen(ctx context.Context, conn *pgxpool.Conn) {
	backoff := 100 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		s.listenLoop(ctx, conn) // returns on ctx cancel or connection error
		if ctx.Err() != nil {
			return
		}
		// Connection dropped. Re-acquire + re-LISTEN with backoff, then resync.
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			c, err := s.Pool.Acquire(ctx)
			if err != nil {
				backoff = minDur(backoff*2, maxBackoff)
				continue
			}
			if _, err := c.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
				c.Release()
				backoff = minDur(backoff*2, maxBackoff)
				continue
			}
			conn = c
			backoff = 100 * time.Millisecond
			// Missed notifications during the gap: replay every local subscriber
			// from its last-seen so no change is silently lost.
			s.resyncAll(ctx)
			break
		}
	}
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (s *Store) listenLoop(ctx context.Context, conn *pgxpool.Conn) {
	defer conn.Release()
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return // ctx cancelled or connection lost; supervisor reconnects + resyncs
		}
		accID, seq, ok := parseNotify(n.Payload)
		if !ok {
			continue
		}
		s.onRemoteChange(ctx, accID, seq)
	}
}

// resyncAll replays the change-log for every account with local subscribers,
// from each subscriber's last-seen offset. Used after a LISTEN reconnect to
// recover notifications missed during the outage.
func (s *Store) resyncAll(ctx context.Context) {
	s.mu.Lock()
	accts := make([]int64, 0, len(s.subs))
	for accID := range s.subs {
		accts = append(accts, accID)
	}
	s.mu.Unlock()
	for _, accID := range accts {
		head, err := s.headOf(accID)
		if err != nil {
			continue
		}
		s.onRemoteChange(ctx, accID, head)
	}
}

// onRemoteChange fans a cross-node notification to local subscribers by
// replaying the log past what each has seen. Same-node writes were already
// delivered rich in-process (see publish), and their lastSeq is advanced there,
// so this path is a no-op for them and only serves OTHER nodes' writes.
//
// All subscribers here are for one account (s.subs is account-keyed), so the log
// is replayed ONCE from the minimum cursor across the behind subscribers and the
// shared result is sliced per subscriber to entries past its own cursor — turning
// the former per-subscriber N+1 (one ReplayChanges query each) into a single query.
func (s *Store) onRemoteChange(ctx context.Context, accID int64, seq store.ModSeq) {
	s.mu.Lock()
	subs := append([]*subscriber(nil), s.subs[accID]...)
	s.mu.Unlock()

	// Only subscribers strictly behind this notification need anything; find the
	// minimum cursor among them so one replay covers them all.
	var behind []*subscriber
	var minCursor store.ModSeq
	for _, sub := range subs {
		if sub.seen() >= seq {
			continue
		}
		if len(behind) == 0 || sub.seen() < minCursor {
			minCursor = sub.seen()
		}
		behind = append(behind, sub)
	}
	if len(behind) == 0 {
		return
	}

	seqs, changes, head, err := s.replayWithSeqs(ctx, accID, minCursor)
	if err != nil || len(changes) == 0 {
		return
	}

	for _, sub := range behind {
		cur := sub.seen()
		// Slice the shared replay to entries strictly past THIS subscriber's cursor
		// (seqs is ascending). A subscriber at a higher cursor gets only its tail; one
		// already at/above head gets nothing.
		start := 0
		for start < len(seqs) && seqs[start] <= cur {
			start++
		}
		if start >= len(changes) {
			continue
		}
		slice := changes[start:]
		// Non-blocking send + advance per subscriber: a slow consumer that can't keep
		// up is dropped here (it resyncs from the log by offset later) without blocking
		// or advancing the others. The shared slice is read-only across subscribers.
		select {
		case sub.comm.Changes <- slice:
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
