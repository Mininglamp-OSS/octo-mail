// Package deliverability is the operator-grade sending subsystem. Its invariant:
// a spammy tenant must never poison another tenant's or the platform's IP
// reputation. Reputation is attributed per (tenant, remote domain) via VERP
// return-path decoding, and the send gate consults it PER TENANT — so pausing
// tenant A for gmail.com never affects tenant B.
//
// This is what separates an operator-grade multi-tenant sender from a demo.
package deliverability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event kinds for reputation.
const (
	KindDelivered = 0
	KindBounce    = 1
	KindComplaint = 2
	KindDeferral  = 3
)

// verpPrefix is the localpart marker for a VERP return-path. It is the single
// source of truth for the token layout shared by the (Signed)VERPToken builders
// and the Parse(Signed)VERP parsers.
const verpPrefix = "bounces+"

// Thresholds beyond which a (tenant, domain) is auto-paused. Deliberately simple
// and explicit; real deployments tune these per remote.
const (
	MinSample        = 20   // don't judge before this many sends
	ComplaintRateMax = 0.01 // 1% complaints -> pause this tenant for this domain
	BounceRateMax    = 0.10 // 10% bounces -> pause
)

// Service records reputation and gates sending.
type Service struct {
	Pool *pgxpool.Pool
}

// GateResult is the send-gate decision for one (tenant, remote domain).
type GateResult struct {
	Allowed bool
	Reason  string
}

// Gate decides whether a tenant may send to a remote domain right now. It reads
// ONLY this tenant's reputation for this domain — isolation is structural.
func (s *Service) Gate(ctx context.Context, tenantID int64, remoteDomain string) (GateResult, error) {
	var sent, complaints, bounces int64
	var paused bool
	err := s.Pool.QueryRow(ctx,
		`SELECT sent, complaints, bounces, paused FROM reputation_score
		 WHERE tenant_id=$1 AND remote_domain=$2`, tenantID, remoteDomain).
		Scan(&sent, &complaints, &bounces, &paused)
	if err == pgx.ErrNoRows {
		return GateResult{Allowed: true, Reason: "no history"}, nil
	}
	if err != nil {
		return GateResult{}, err
	}
	if paused {
		return GateResult{Allowed: false, Reason: "tenant paused for domain"}, nil
	}
	return GateResult{Allowed: true}, nil
}

// RecordSent increments the send counter for a (tenant, domain).
func (s *Service) RecordSent(ctx context.Context, tenantID int64, remoteDomain string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO reputation_score (tenant_id, remote_domain, sent) VALUES ($1,$2,1)
		 ON CONFLICT (tenant_id, remote_domain)
		 DO UPDATE SET sent = reputation_score.sent + 1, updated_at = now()`,
		tenantID, remoteDomain)
	return err
}

// RecordEvent logs a reputation event (bounce/complaint) and re-evaluates the
// (tenant, domain) score, auto-pausing that tenant for that domain if it crosses
// a threshold. Crucially scoped to one tenant — never touches others.
//
// msgID is the originating outbound message id (from the signed VERP token) for
// inbound bounce/complaint ingest; pass 0 when there is no single originating
// message (e.g. a delivery-time hard bounce). When msgID > 0 the event is
// idempotent per (tenant, msgID): a replayed/redelivered report inserts nothing
// and does NOT bump the counters, so an attacker who captures a victim's
// in-the-clear signed VERP address can't replay it to force auto-pause.
func (s *Service) RecordEvent(ctx context.Context, tenantID, accountID int64, kind int, remoteDomain string, msgID int64) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Insert the event. With a msgID, dedup on (tenant, msg_id): a replay
		// conflicts and inserts zero rows, and we then stop before touching the
		// counters. Without a msgID, every call is a distinct event (legacy path).
		if msgID > 0 {
			ct, err := tx.Exec(ctx,
				`INSERT INTO reputation_events (tenant_id, account_id, kind, remote_domain, msg_id)
				 VALUES ($1,$2,$3,$4,$5)
				 ON CONFLICT (tenant_id, msg_id) WHERE msg_id IS NOT NULL DO NOTHING`,
				tenantID, nullIf0(accountID), kind, remoteDomain, msgID)
			if err != nil {
				return err
			}
			if ct.RowsAffected() == 0 {
				return nil // replay/redelivery of an already-recorded report — no-op
			}
		} else {
			if _, err := tx.Exec(ctx,
				`INSERT INTO reputation_events (tenant_id, account_id, kind, remote_domain)
				 VALUES ($1,$2,$3,$4)`, tenantID, nullIf0(accountID), kind, remoteDomain); err != nil {
				return err
			}
		}
		col := ""
		switch kind {
		case KindComplaint:
			col = "complaints"
		case KindBounce:
			col = "bounces"
		default:
			return nil // delivered/deferral don't move the pause needle here
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`INSERT INTO reputation_score (tenant_id, remote_domain, %s) VALUES ($1,$2,1)
			 ON CONFLICT (tenant_id, remote_domain)
			 DO UPDATE SET %s = reputation_score.%s + 1, updated_at = now()`, col, col, col),
			tenantID, remoteDomain); err != nil {
			return err
		}
		// Re-evaluate pause for THIS tenant+domain only.
		var sent, complaints, bounces int64
		if err := tx.QueryRow(ctx,
			`SELECT sent, complaints, bounces FROM reputation_score WHERE tenant_id=$1 AND remote_domain=$2`,
			tenantID, remoteDomain).Scan(&sent, &complaints, &bounces); err != nil {
			return err
		}
		if sent >= MinSample {
			cr := float64(complaints) / float64(sent)
			br := float64(bounces) / float64(sent)
			if cr > ComplaintRateMax || br > BounceRateMax {
				if _, err := tx.Exec(ctx,
					`UPDATE reputation_score SET paused=true, updated_at=now()
					 WHERE tenant_id=$1 AND remote_domain=$2`, tenantID, remoteDomain); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// --- VERP return-path attribution ---

// VERPToken builds a return-path localpart that encodes the sending tenant and
// message id, so bounces/complaints route back to the right tenant:
//
//	bounces+<tenantID>.<msgID>@<bounceDomain>
//
// Prefer SignedVERPToken in production: an unsigned token is forgeable (tenant
// ids are small integers), which lets an unauthenticated sender attribute
// bounces/complaints to a victim tenant. This form is retained for tests and for
// deployments that have not configured a VERP key.
func VERPToken(tenantID, msgID int64) string {
	return verpPrefix + strconv.FormatInt(tenantID, 10) + "." + strconv.FormatInt(msgID, 10)
}

// ParseVERP decodes an unsigned 2-part VERP localpart back to (tenantID, msgID).
// Accepts the full localpart (with or without the "bounces+" prefix). It does NOT
// authenticate — see ParseSignedVERP for the forgery-resistant form, which is the
// only caller for a signed 3-part token.
func ParseVERP(localpart string) (tenantID, msgID int64, ok bool) {
	lp := strings.TrimPrefix(strings.ToLower(localpart), verpPrefix)
	a, b, found := strings.Cut(lp, ".")
	if !found {
		return 0, 0, false
	}
	ti, err1 := strconv.ParseInt(a, 10, 64)
	mi, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return ti, mi, true
}

// verpMAC computes the authentication tag for (tenantID, msgID) under key: the
// first 10 bytes of HMAC-SHA256, lowercase base32 (no padding) — short enough
// for a localpart, wide enough (80 bits) to make forgery infeasible.
// verpMAC computes the authentication tag for (tenantID, msgID) under key: the
// first 12 bytes of HMAC-SHA256, lowercase base32 (no padding) — 96 bits, short
// enough for a localpart (20 base32 chars) yet a wide margin against the bounce
// MX being an online forgery oracle. Truncation of an HMAC is sound (RFC 2104).
func verpMAC(tenantID, msgID int64, key []byte) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d.%d", tenantID, msgID)
	sum := mac.Sum(nil)[:12]
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum))
}

// SignedVERPToken builds an HMAC-authenticated VERP localpart:
//
//	bounces+<tenantID>.<msgID>.<mac>
//
// A recipient/attacker cannot forge a token for another tenant without key. When
// key is empty it falls back to the unsigned VERPToken.
func SignedVERPToken(tenantID, msgID int64, key []byte) string {
	if len(key) == 0 {
		return VERPToken(tenantID, msgID)
	}
	return VERPToken(tenantID, msgID) + "." + verpMAC(tenantID, msgID, key)
}

// ParseSignedVERP decodes AND authenticates a VERP localpart against key. It
// returns ok=false for a missing/invalid signature, so a forged token attributes
// nothing. When key is empty it accepts the unsigned form (ParseVERP) — matching
// SignedVERPToken's fallback so a keyless deployment still round-trips.
//
// When a key IS set, ONLY the signed 3-part form is accepted: a MAC-less 2-part
// token is rejected. Accepting it would be a forgery bypass (an attacker just
// omits the MAC to attribute a bounce/complaint to any victim tenant), and there
// is no legitimate keyless→keyed rollout window to protect because the node
// refuses to enable the bounce domain without a key (see checkVERPConfig).
//
// The localpart is lowercased first: SignedVERPToken emits an all-lowercase token
// (digits, ".", and a lowercased base32 tag), but a bounce/DSN may return through
// an intermediary that re-cases the localpart. Lowercasing makes verification
// robust without weakening it (the token alphabet has no case significance). The
// tenant/msg fields are parsed canonically (no leading zeros / sign), so one
// logical token has exactly one valid string form.
func ParseSignedVERP(localpart string, key []byte) (tenantID, msgID int64, ok bool) {
	if len(key) == 0 {
		return ParseVERP(localpart)
	}
	lp := strings.TrimPrefix(strings.ToLower(localpart), verpPrefix)
	parts := strings.Split(lp, ".")
	// With a key configured, require the signed 3-part form. A 2-part (MAC-less)
	// token must NOT authenticate — accepting it would let anyone forge attribution
	// for a victim tenant simply by dropping the MAC.
	if len(parts) != 3 {
		return 0, 0, false
	}
	ti, ok1 := parseCanonInt(parts[0])
	mi, ok2 := parseCanonInt(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(verpMAC(ti, mi, key))) {
		return 0, 0, false
	}
	return ti, mi, true
}

// parseCanonInt parses a canonical non-negative decimal (no sign, no leading
// zeros beyond "0" itself), so a signed token has exactly one valid spelling and
// can't be replayed as "007"/"+7".
func parseCanonInt(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != s {
		return 0, false
	}
	return n, true
}

func nullIf0(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
