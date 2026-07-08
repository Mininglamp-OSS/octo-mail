// FBL (Feedback Loop) and bounce ingestion. When a mailbox provider forwards an
// abuse complaint, it arrives as an ARF message (RFC 5965: multipart/report with
// report-type=feedback-report). The original message we sent is embedded, and
// its return-path carries our VERP token — so a complaint is attributed to the
// exact sending tenant, never to the platform aggregate. This closes the "FBL
// parsing not wired" boundary from P5.
package deliverability

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
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

// reportKindAndDomain classifies an inbound report to the bounce domain and
// extracts the affected recipient domain, so the reputation event lands in the
// same (tenant, domain) row that outbound `sent` feeds (driving auto-pause). It
// distinguishes an ARF complaint (report-type=feedback-report) from a DSN bounce
// (report-type=delivery-status, or any non-ARF message). Domain is best-effort
// ("" if the provider redacted it); classification never depends on a VERP
// inside the embedded original (attribution comes from the signed recipient
// token in IngestReport).
func reportKindAndDomain(raw []byte) (kind int, domain string) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return KindBounce, ""
	}
	mediaType, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	isReport := strings.EqualFold(mediaType, "multipart/report")
	reportType := params["report-type"]
	kind = KindBounce
	if isReport && strings.EqualFold(reportType, "feedback-report") {
		kind = KindComplaint
	}
	if !isReport || params["boundary"] == "" {
		return kind, ""
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		pType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		body, _ := io.ReadAll(part)
		switch {
		case strings.EqualFold(pType, "message/feedback-report"):
			if d := addr.Domain(fieldValue(body, "Original-Rcpt-To")); d != "" {
				return kind, d
			}
		case strings.EqualFold(pType, "message/delivery-status"):
			// DSN: Final-Recipient: rfc822; user@failed.example
			if fr := fieldValue(body, "Final-Recipient"); fr != "" {
				if i := strings.LastIndexByte(fr, ';'); i >= 0 {
					fr = fr[i+1:]
				}
				if d := addr.Domain(fr); d != "" {
					return kind, d
				}
			}
		case strings.EqualFold(pType, "message/rfc822"), strings.EqualFold(pType, "text/rfc822-headers"):
			if d := addr.Domain(fieldValue(body, "To")); d != "" {
				return kind, d
			}
		}
	}
	return kind, ""
}

// IngestReport handles an inbound message delivered to the bounce domain (an ARF
// complaint or a DSN bounce). Attribution is taken from the SIGNED VERP token in
// the recipient localpart the message was addressed to (verpLocalpart) -- our own
// authenticated return-path -- NOT from attacker-controllable report contents, so
// a forged report cannot attribute a bounce/complaint to a victim tenant. The
// report body is used only to distinguish complaint (ARF) from bounce (DSN). key
// is the VERP signing key; empty disables authentication (dev only). ok=false
// when the recipient token does not authenticate.
func (s *Service) IngestReport(ctx context.Context, verpLocalpart string, key, raw []byte) (Complaint, bool, error) {
	tenantID, msgID, ok := ParseSignedVERP(verpLocalpart, key)
	if !ok {
		return Complaint{}, false, nil // unauthenticated/forged recipient token
	}
	// Classify (complaint vs bounce) and extract the affected recipient domain so
	// the event lands in the same (tenant, domain) reputation row outbound `sent`
	// feeds — which is what drives auto-pause. Attribution (tenant) already came
	// from the authenticated recipient token above.
	kind, domain := reportKindAndDomain(raw)
	c := Complaint{TenantID: tenantID, MsgID: msgID, RemoteDomain: domain, Kind: kind}
	if err := s.RecordEvent(ctx, c.TenantID, 0, c.Kind, c.RemoteDomain); err != nil {
		return Complaint{}, false, err
	}
	return c, true, nil
}

// fieldValue extracts a header field value from raw header bytes (case-insensitive).
func fieldValue(raw []byte, name string) string {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.IndexByte(line, ':'); i > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:i]), name) {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}
