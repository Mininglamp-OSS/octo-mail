package deliverability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
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
	// Secret, when set, HMAC-SHA256-signs the payload so the receiver can verify
	// authenticity (sent as X-Octo-Mail-Signature: sha256=<hex>). Empty = unsigned.
	Secret []byte
	// Log, if set, records DB-update anomalies (a success/reschedule Exec that
	// errored or touched no row — which would otherwise cause silent re-delivery).
	Log *slog.Logger
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
		client = defaultWebhookClient()
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
			// Fence every state update on the lease we still hold: if another node
			// stole the (expired) lease during a slow POST, our UPDATE touches no row
			// and we do NOT double-mark — the current leaseholder owns the outcome.
			w.exec(ctx, "mark-delivered", j.id,
				`UPDATE webhook_events SET delivered=true, leased_by=NULL WHERE id=$1 AND leased_by=$2`, j.id, w.NodeID)
			delivered++
			continue
		}
		att := j.attempts + 1
		if att >= j.maxAtt {
			// Give up: mark delivered=false but stop retrying by pushing next_attempt far out.
			w.exec(ctx, "exhaust", j.id,
				`UPDATE webhook_events SET attempts=$2, leased_by=NULL, next_attempt=now()+interval '100 years' WHERE id=$1 AND leased_by=$3`, j.id, att, w.NodeID)
		} else {
			w.exec(ctx, "reschedule", j.id,
				`UPDATE webhook_events SET attempts=$2, leased_by=NULL, next_attempt=now()+make_interval(secs => $3) WHERE id=$1 AND leased_by=$4`,
				j.id, att, backoff.Seconds(), w.NodeID)
		}
	}
	return delivered, nil
}

// exec runs a state-update statement and surfaces anomalies: an error, or a
// statement that touched no row (e.g. the lease was stolen after a slow POST),
// means the event's state did not advance as intended and it may be re-delivered.
// The prior code discarded both, so this failure was silent.
func (w *WebhookWorker) exec(ctx context.Context, op string, id int64, sql string, args ...any) {
	tag, err := w.Pool.Exec(ctx, sql, args...)
	if err != nil {
		if w.Log != nil {
			w.Log.WarnContext(ctx, "webhook state update failed", "op", op, "event", id, "err", err)
		}
		return
	}
	if tag.RowsAffected() != 1 && w.Log != nil {
		w.Log.WarnContext(ctx, "webhook state update touched no row (lease lost? possible re-delivery)",
			"op", op, "event", id, "rows", tag.RowsAffected())
	}
}

func (w *WebhookWorker) post(ctx context.Context, client *http.Client, url, event string, payload []byte) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Octo-Mail-Event", event)
	if len(w.Secret) > 0 {
		mac := hmac.New(sha256.New, w.Secret)
		mac.Write(payload)
		req.Header.Set("X-Octo-Mail-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// defaultWebhookClient builds an HTTP client hardened against SSRF: it refuses
// redirects (a 30x to an internal host can't be followed) and blocks dialing any
// non-public IP (loopback, private, link-local incl. 169.254.169.254 cloud
// metadata, unique-local, unspecified). The guard checks the ACTUAL resolved IP
// at dial time, so a hostname that resolves to a private address is still blocked
// (DNS-rebinding-resistant). The webhook URL is operator-configured today, but
// this protects any future per-tenant URL from becoming an SSRF sink.
func defaultWebhookClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("webhook: redirects are not followed")
		},
		Transport: &http.Transport{
			DialContext: safeDialContext,
		},
	}
}

// safeDialContext resolves the target and dials only if every resolved address is
// a public IP; otherwise it refuses. Applied per-connection so the check binds to
// the address actually connected to.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	for _, ip := range ips {
		if !isBlockedIP(ip.IP) {
			// Dial this specific vetted IP so we connect to exactly what we checked.
			return d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
	}
	return nil, fmt.Errorf("webhook: refusing to connect to non-public address for host %q", host)
}

// isBlockedIP reports whether ip is one a webhook must never target: loopback,
// private (RFC 1918 / ULA), link-local (incl. 169.254.169.254), unspecified, or
// multicast. IPv4-mapped IPv6 is normalized first so a mapped private address
// can't slip through.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}
