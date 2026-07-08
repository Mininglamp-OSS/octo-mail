// FBL (Feedback Loop) and bounce ingestion. When a mailbox provider forwards an
// abuse complaint it arrives as an ARF message (RFC 5965: multipart/report with
// report-type=feedback-report); a DSN bounce arrives as report-type=delivery-status.
// Both are delivered to our VERP bounce domain, so the recipient localpart carries
// our own HMAC-signed VERP token. Attribution (tenant) and the affected recipient
// domain both come from that authenticated token + our outbound send record — NOT
// from the attacker-controllable report body, which is trusted only to tell a
// complaint apart from a bounce. This closes the "FBL parsing not wired" boundary
// from P5 without opening a cross-tenant/cross-domain forgery vector.
package deliverability

import (
	"bytes"
	"context"
	"mime"
	"net/mail"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/addr"
)

// Complaint is the outcome of parsing an ARF/bounce report.
type Complaint struct {
	TenantID     int64
	MsgID        int64
	RemoteDomain string // the complaining/recipient domain
	Kind         int    // KindComplaint or KindBounce
}

// reportKind classifies an inbound report to the bounce domain: an ARF complaint
// (report-type=feedback-report) vs a DSN bounce (report-type=delivery-status, or
// any non-ARF message). This is the ONLY thing the (attacker-controllable) report
// body is trusted for — the affected domain and tenant come from authenticated
// state, not the body (see IngestReport). A complaint has a much stricter
// auto-pause threshold than a bounce, but mis-classifying can only move a report
// between the sender's OWN two counters; it can't cross tenants or domains.
func reportKind(raw []byte) int {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return KindBounce
	}
	mediaType, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if strings.EqualFold(mediaType, "multipart/report") && strings.EqualFold(params["report-type"], "feedback-report") {
		return KindComplaint
	}
	return KindBounce
}

// IngestReport handles an inbound message delivered to the bounce domain (an ARF
// complaint or a DSN bounce). Attribution is taken from the SIGNED VERP token in
// the recipient localpart the message was addressed to (verpLocalpart) -- our own
// authenticated return-path -- NOT from attacker-controllable report contents, so
// a forged report cannot attribute a bounce/complaint to a victim tenant.
//
// The affected recipient DOMAIN is likewise authenticated: it is looked up from
// the outbound queue log by the signed (tenant, msgID), i.e. the domain WE sent
// that message to — never the report body (a report recipient holds a valid token
// for their own bounce address and could otherwise claim any domain to poison a
// tenant's reputation for, say, gmail.com). The report body is used ONLY to
// distinguish complaint (ARF) from bounce (DSN). If the authenticated domain is
// no longer available (queue log swept past retention), the event is recorded
// with an empty domain — safe (it can't feed a forged per-domain row) though it
// won't drive that domain's auto-pause. key is the VERP signing key; empty
// disables authentication (dev only). ok=false when the recipient token does not
// authenticate.
func (s *Service) IngestReport(ctx context.Context, verpLocalpart string, key, raw []byte) (Complaint, bool, error) {
	tenantID, msgID, ok := ParseSignedVERP(verpLocalpart, key)
	if !ok {
		return Complaint{}, false, nil // unauthenticated/forged recipient token
	}
	// Classify (complaint vs bounce) from the report body — the only thing the
	// body is trusted for. The domain comes from authenticated send-state below.
	kind := reportKind(raw)
	// Authenticated affected domain: what we actually sent this msgID to. Falls
	// back to "" (safe) if the send record has aged out of the queue log.
	domain := s.sentDomain(ctx, tenantID, msgID)
	c := Complaint{TenantID: tenantID, MsgID: msgID, RemoteDomain: domain, Kind: kind}
	if err := s.RecordEvent(ctx, c.TenantID, 0, c.Kind, c.RemoteDomain); err != nil {
		return Complaint{}, false, err
	}
	return c, true, nil
}

// sentDomain returns the recipient domain we delivered (tenant, msgID) to, from
// the durable outbound queue log — the authenticated source of the affected
// domain for reputation. Scoped to tenantID so one tenant's token can never
// resolve another tenant's recipient. Returns "" if no such record exists.
func (s *Service) sentDomain(ctx context.Context, tenantID, msgID int64) string {
	var rcpt string
	if err := s.Pool.QueryRow(ctx,
		`SELECT rcpt_to FROM queue_log
		 WHERE queue_id=$1 AND tenant_id=$2 AND rcpt_to <> ''
		 ORDER BY id LIMIT 1`, msgID, tenantID).Scan(&rcpt); err != nil {
		return "" // no authenticated record (swept, or never logged)
	}
	return addr.Domain(rcpt)
}
