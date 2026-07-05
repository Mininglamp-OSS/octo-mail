package deliverability

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookWorker delivers queued webhook_events over HTTP with a lease, mirroring
// the mail queue's failover pattern: any node claims due events with FOR UPDATE
// SKIP LOCKED, POSTs the payload, and marks delivered or reschedules with
// backoff. This is the consumer side of Webhooks.Enqueue.
type WebhookWorker struct {
	Pool    *pgxpool.Pool
	NodeID  string
	Client  *http.Client
	Batch   int
	Backoff time.Duration
}

// RunOnce claims and attempts up to Batch due webhook events. Returns the number
// delivered. Injectable Client lets tests point at an httptest server.
func (w *WebhookWorker) RunOnce(ctx context.Context) (int, error) {
	batch := w.Batch
	if batch <= 0 {
		batch = 20
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	backoff := w.Backoff
	if backoff == 0 {
		backoff = 30 * time.Second
	}

	rows, err := w.Pool.Query(ctx,
		`UPDATE webhook_events SET leased_by=$1, lease_until=now()+interval '30 seconds'
		 WHERE id IN (
		   SELECT id FROM webhook_events
		   WHERE NOT delivered AND next_attempt<=now() AND (leased_by IS NULL OR lease_until<now())
		   ORDER BY next_attempt FOR UPDATE SKIP LOCKED LIMIT $2)
		 RETURNING id, url, event, payload, attempts, max_attempts`, w.NodeID, batch)
	if err != nil {
		return 0, err
	}
	type job struct {
		id               int64
		url, event       string
		payload          []byte
		attempts, maxAtt int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.url, &j.event, &j.payload, &j.attempts, &j.maxAtt); err != nil {
			rows.Close()
			return 0, err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	delivered := 0
	for _, j := range jobs {
		ok := w.post(ctx, client, j.url, j.event, j.payload)
		if ok {
			w.Pool.Exec(ctx, `UPDATE webhook_events SET delivered=true, leased_by=NULL WHERE id=$1`, j.id)
			delivered++
			continue
		}
		att := j.attempts + 1
		if att >= j.maxAtt {
			// Give up: mark delivered=false but stop retrying by pushing next_attempt far out.
			w.Pool.Exec(ctx, `UPDATE webhook_events SET attempts=$2, leased_by=NULL, next_attempt=now()+interval '100 years' WHERE id=$1`, j.id, att)
		} else {
			w.Pool.Exec(ctx, `UPDATE webhook_events SET attempts=$2, leased_by=NULL, next_attempt=now()+$3 WHERE id=$1`,
				j.id, att, backoff)
		}
	}
	return delivered, nil
}

func (w *WebhookWorker) post(ctx context.Context, client *http.Client, url, event string, payload []byte) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Octo-Mail-Event", event)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
