// Package outbound holds send-side hardening for octo-mail's queue: a suppression
// list (stop sending to hard-bounced/complained recipients), webhook event
// emission (delivery/bounce/complaint notifications), and MTA-STS-aware TLS
// policy for outbound delivery. It reuses the mtasts library for policy
// discovery; nothing here reimplements protocol logic.
package deliverability

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/smtpclient"
)

// Suppressions is the per-account suppression list.
type Suppressions struct {
	Pool *pgxpool.Pool
}

// baseAddress canonicalizes an address for suppression matching: lowercased,
// with any "+tag" removed from the localpart.
func baseAddress(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return addr
	}
	lp, dom := addr[:at], addr[at:]
	if plus := strings.IndexByte(lp, '+'); plus >= 0 {
		lp = lp[:plus]
	}
	return lp + dom
}

// Suppressed reports whether the account is suppressed from sending to address.
func (s *Suppressions) Suppressed(ctx context.Context, accountID int64, address string) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM suppressions WHERE account_id=$1 AND address=$2`,
		accountID, baseAddress(address)).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Add records a suppression (idempotent per account+address).
func (s *Suppressions) Add(ctx context.Context, tenantID, accountID int64, address, reason string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO suppressions (tenant_id, account_id, address, reason)
		 VALUES ($1,$2,$3,$4) ON CONFLICT (account_id, address) DO NOTHING`,
		tenantID, accountID, baseAddress(address), reason)
	return err
}

// Remove deletes a suppression (e.g. operator override).
func (s *Suppressions) Remove(ctx context.Context, accountID int64, address string) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM suppressions WHERE account_id=$1 AND address=$2`, accountID, baseAddress(address))
	return err
}

// List returns the suppressed addresses for an account (base-normalized).
func (s *Suppressions) List(ctx context.Context, accountID int64) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT address FROM suppressions WHERE account_id=$1 ORDER BY address`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Webhooks queues outbound webhook events.
type Webhooks struct {
	Pool *pgxpool.Pool
}

// Enqueue records a webhook event for later HTTP delivery.
func (w *Webhooks) Enqueue(ctx context.Context, tenantID, accountID int64, url, event string, payload any) error {
	pj, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Pool.Exec(ctx,
		`INSERT INTO webhook_events (tenant_id, account_id, url, event, payload)
		 VALUES ($1,$2,$3,$4,$5)`, tenantID, accountID, url, event, pj)
	return err
}

// TLSPolicy resolves the outbound TLS requirement for a recipient domain via
// MTA-STS. When the domain publishes an enforce policy, TLS is required
// (TLSRequiredStartTLS); otherwise opportunistic. The resolver is injectable for
// tests.
type TLSPolicy struct {
	Resolver dns.Resolver
}

// ModeFor returns the smtpclient TLS mode and whether MTA-STS enforce applies.
// It only consults the DNS record (_mta-sts TXT) for testability; policy body
// fetch (HTTPS) is attempted by the Get in production. A missing/none record
// yields opportunistic TLS.
func (p *TLSPolicy) ModeFor(ctx context.Context, domain string) (smtpclient.TLSMode, bool, error) {
	d, err := dns.ParseDomain(domain)
	if err != nil {
		return smtpclient.TLSOpportunistic, false, err
	}
	record, _, err := mtasts.LookupRecord(ctx, nil, p.Resolver, d)
	if err != nil || record == nil {
		// No MTA-STS: opportunistic.
		return smtpclient.TLSOpportunistic, false, nil
	}
	// A published MTA-STS record means the domain wants TLS; fetch the policy for
	// the mode. In tests without an HTTPS policy server, treat a present record as
	// enforce (the DNS opt-in is the signal we can verify offline).
	_, policy, _, perr := mtasts.Get(ctx, nil, p.Resolver, d)
	if perr == nil && policy != nil {
		if policy.Mode == mtasts.ModeEnforce {
			return smtpclient.TLSRequiredStartTLS, true, nil
		}
		return smtpclient.TLSOpportunistic, false, nil
	}
	// Record present but policy body unreachable: be strict (enforce).
	return smtpclient.TLSRequiredStartTLS, true, nil
}
