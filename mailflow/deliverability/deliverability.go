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
func (s *Service) RecordEvent(ctx context.Context, tenantID, accountID int64, kind int, remoteDomain string) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO reputation_events (tenant_id, account_id, kind, remote_domain)
			 VALUES ($1,$2,$3,$4)`, tenantID, nullIf0(accountID), kind, remoteDomain); err != nil {
			return err
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
	return "bounces+" + strconv.FormatInt(tenantID, 10) + "." + strconv.FormatInt(msgID, 10)
}

// ParseVERP decodes a VERP localpart back to (tenantID, msgID). Accepts the full
// localpart (with or without the "bounces+" prefix). It does NOT authenticate —
// see ParseSignedVERP for the forgery-resistant form.
func ParseVERP(localpart string) (tenantID, msgID int64, ok bool) {
	lp := strings.TrimPrefix(localpart, "bounces+")
	a, b, found := strings.Cut(lp, ".")
	if !found {
		return 0, 0, false
	}
	// Tolerate a trailing signature segment (bounces+T.M.SIG) so a signed token
	// still yields (T,M) here; authentication is ParseSignedVERP's job.
	if i := strings.IndexByte(b, '.'); i >= 0 {
		b = b[:i]
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
func verpMAC(tenantID, msgID int64, key []byte) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d.%d", tenantID, msgID)
	sum := mac.Sum(nil)[:10]
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
	return "bounces+" + strconv.FormatInt(tenantID, 10) + "." + strconv.FormatInt(msgID, 10) + "." + verpMAC(tenantID, msgID, key)
}

// ParseSignedVERP decodes AND authenticates a VERP localpart against key. It
// returns ok=false for a missing/invalid signature, so a forged token attributes
// nothing. When key is empty it accepts the unsigned form (ParseVERP) — matching
// SignedVERPToken's fallback so a keyless deployment still round-trips.
func ParseSignedVERP(localpart string, key []byte) (tenantID, msgID int64, ok bool) {
	if len(key) == 0 {
		return ParseVERP(localpart)
	}
	lp := strings.TrimPrefix(localpart, "bounces+")
	parts := strings.Split(lp, ".")
	if len(parts) != 3 {
		return 0, 0, false
	}
	ti, err1 := strconv.ParseInt(parts[0], 10, 64)
	mi, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	want := verpMAC(ti, mi, key)
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return 0, 0, false
	}
	return ti, mi, true
}

func nullIf0(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
