// FBL (Feedback Loop) and bounce ingestion. When a mailbox provider forwards an
// abuse complaint, it arrives as an ARF message (RFC 5965: multipart/report with
// report-type=feedback-report). The original message we sent is embedded, and
// its return-path carries our VERP token — so a complaint is attributed to the
// exact sending tenant, never to the platform aggregate. This closes the "FBL
// parsing not wired" boundary from P5.
package deliverability

import (
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/addr"
	"github.com/mjl-/mox/smtp"
)

// Complaint is the outcome of parsing an ARF/bounce report.
type Complaint struct {
	TenantID     int64
	MsgID        int64
	RemoteDomain string // the complaining/recipient domain
	Kind         int    // KindComplaint or KindBounce
}

// ParseARF extracts the tenant/message attribution from an ARF feedback report
// (RFC 5965). It finds the VERP token in the embedded original message's
// Return-Path / From, and the complained-about recipient's domain from the
// feedback report's Original-Rcpt-To (or the embedded To). Returns ok=false if
// the message is not a parseable ARF report or lacks a VERP token.
func ParseARF(raw []byte) (Complaint, bool) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return Complaint{}, false
	}
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mediaType, "multipart/report") {
		return Complaint{}, false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return Complaint{}, false
	}

	mr := multipart.NewReader(msg.Body, boundary)
	var reportRcptDomain string
	var verpLocalpart string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		pType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		body, _ := io.ReadAll(part)
		switch {
		case strings.EqualFold(pType, "message/feedback-report"):
			// Fields like "Original-Rcpt-To: <you@remote.example>".
			reportRcptDomain = addr.Domain(fieldValue(body, "Original-Rcpt-To"))
		case strings.EqualFold(pType, "message/rfc822"), strings.EqualFold(pType, "text/rfc822-headers"):
			// The original message we sent. Its Return-Path localpart is the VERP.
			verpLocalpart = localpartOf(fieldValue(body, "Return-Path"))
			if verpLocalpart == "" {
				// Some providers strip Return-Path; fall back to a VERP in To of
				// the embedded original if present (defensive).
				verpLocalpart = localpartOf(fieldValue(body, "X-Return-Path"))
			}
			if reportRcptDomain == "" {
				reportRcptDomain = addr.Domain(fieldValue(body, "To"))
			}
		}
	}

	tenantID, msgID, ok := ParseVERP(verpLocalpart)
	if !ok {
		return Complaint{}, false
	}
	return Complaint{
		TenantID:     tenantID,
		MsgID:        msgID,
		RemoteDomain: reportRcptDomain,
		Kind:         KindComplaint,
	}, true
}

// RecordComplaint parses an ARF report and records the complaint against the
// attributed tenant. Returns the parsed complaint. It never attributes to the
// platform: if no VERP token is found, it returns an error rather than guessing.
func (s *Service) RecordComplaint(ctx context.Context, raw []byte) (Complaint, error) {
	c, ok := ParseARF(raw)
	if !ok {
		return Complaint{}, fmt.Errorf("not a VERP-attributable ARF report")
	}
	if err := s.RecordEvent(ctx, c.TenantID, 0, c.Kind, c.RemoteDomain); err != nil {
		return Complaint{}, err
	}
	return c, nil
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

// localpartOf returns the localpart of an address like "<lp@dom>" or "lp@dom".
func localpartOf(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	if p, err := smtp.ParseAddress(addr); err == nil {
		return string(p.Localpart)
	}
	if i := strings.LastIndexByte(addr, '@'); i > 0 {
		return addr[:i]
	}
	return ""
}
