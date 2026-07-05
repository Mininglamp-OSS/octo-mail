// Package submit is the outbound submission path: an authenticated account hands
// off a composed message, which is stored once in the blob store and enqueued
// (one queue row per recipient) for the shared outbound queue to deliver. This
// is the outbound counterpart to inbound delivery (directory.InboundTarget).
package submit

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/smtp"
)

// Submitter enqueues outbound mail for delivery.
type Submitter struct {
	Pool *pgxpool.Pool
	Blob blob.Store
}

// Submit stores the raw message body in the tenant's blob store and enqueues one
// delivery row per recipient. Returns the enqueued queue message ids.
func (s *Submitter) Submit(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error) {
	return s.SubmitAt(ctx, tenantID, accountID, mailFrom, rcptTo, raw, time.Time{})
}

// SubmitAt is like Submit but defers the first delivery attempt of every enqueued
// message until notBefore (FUTURERELEASE, RFC 4865). A zero notBefore delivers as
// soon as possible (identical to Submit).
func (s *Submitter) SubmitAt(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte, notBefore time.Time) ([]int64, error) {
	return s.SubmitDSN(ctx, tenantID, accountID, mailFrom, rcptTo, raw, notBefore, DSNParams{})
}

// DSNParams carries RFC 3461 DSN request parameters from an SMTP submission into
// the queue so the DSN generator can honor them. Ret (FULL/HDRS) and EnvID are
// per-message; Notify and ORcpt are per-recipient, keyed by recipient address
// (a missing entry means the SMTP default).
type DSNParams struct {
	Ret    string            // FULL | HDRS ("" = default)
	EnvID  string            // envelope id echoed in the DSN
	Notify map[string]string // rcpt address → comma list of NEVER/SUCCESS/FAILURE/DELAY
	ORcpt  map[string]string // rcpt address → original recipient (ORCPT)
}

// SubmitDSN is SubmitAt plus per-recipient RFC 3461 DSN parameters.
func (s *Submitter) SubmitDSN(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte, notBefore time.Time, dsnp DSNParams) ([]int64, error) {
	if len(rcptTo) == 0 {
		return nil, fmt.Errorf("no recipients")
	}
	// Validate addresses up front.
	if _, err := smtp.ParseAddress(mailFrom); err != nil && mailFrom != "" {
		return nil, fmt.Errorf("invalid mail from %q: %w", mailFrom, err)
	}
	for _, r := range rcptTo {
		if _, err := smtp.ParseAddress(r); err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", r, err)
		}
	}

	ref, size, err := s.Blob.Put(ctx, tenantID, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("storing message body: %w", err)
	}

	ids := make([]int64, 0, len(rcptTo))
	for _, r := range rcptTo {
		id, err := queue.Enqueue(ctx, s.Pool, queue.Msg{
			TenantID:  tenantID,
			AccountID: accountID,
			MailFrom:  mailFrom,
			RcptTo:    r,
			BlobRef:   string(ref),
			Size:      size,
			NotBefore: notBefore,
			Ret:       dsnp.Ret,
			EnvID:     dsnp.EnvID,
			Notify:    dsnp.Notify[r],
			ORcpt:     dsnp.ORcpt[r],
		})
		if err != nil {
			return ids, fmt.Errorf("enqueue for %s: %w", r, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}
