package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// VacationGet returns the account's stored JMAP vacation response, or ok=false
// if none has been set yet.
func (a *account) VacationGet(ctx context.Context) (store.VacationResponse, bool, error) {
	var v store.VacationResponse
	var from, to *time.Time
	err := a.s.Pool.QueryRow(ctx,
		`SELECT enabled, subject, text_body, html_body, from_date, to_date
		 FROM vacation_response WHERE account_id=$1`, a.id).
		Scan(&v.Enabled, &v.Subject, &v.TextBody, &v.HTMLBody, &from, &to)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.VacationResponse{}, false, nil
	}
	if err != nil {
		return store.VacationResponse{}, false, err
	}
	if from != nil {
		v.FromDate = *from
	}
	if to != nil {
		v.ToDate = *to
	}
	return v, true, nil
}

// VacationSet upserts the account's vacation response.
func (a *account) VacationSet(ctx context.Context, v store.VacationResponse) error {
	var from, to *time.Time
	if !v.FromDate.IsZero() {
		from = &v.FromDate
	}
	if !v.ToDate.IsZero() {
		to = &v.ToDate
	}
	_, err := a.s.Pool.Exec(ctx,
		`INSERT INTO vacation_response (account_id, enabled, subject, text_body, html_body, from_date, to_date)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (account_id) DO UPDATE SET
		   enabled=EXCLUDED.enabled, subject=EXCLUDED.subject, text_body=EXCLUDED.text_body,
		   html_body=EXCLUDED.html_body, from_date=EXCLUDED.from_date, to_date=EXCLUDED.to_date`,
		a.id, v.Enabled, v.Subject, v.TextBody, v.HTMLBody, from, to)
	return err
}

// VacationShouldReply records an auto-reply to sender and reports whether this is
// the first reply within the dedup window (24h). Uses INSERT ... ON CONFLICT so
// concurrent deliveries cannot double-send.
func (a *account) VacationShouldReply(ctx context.Context, sender string) (bool, error) {
	tag, err := a.s.Pool.Exec(ctx,
		`INSERT INTO vacation_sent (account_id, recipient) VALUES ($1,$2)
		 ON CONFLICT (account_id, recipient)
		 DO UPDATE SET sent_at=now() WHERE vacation_sent.sent_at < now() - interval '24 hours'`,
		a.id, sender)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
