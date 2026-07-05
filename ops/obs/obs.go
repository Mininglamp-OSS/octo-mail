// Package obs is octo-mail's observability surface: Prometheus metrics for the mail
// pipeline (deliveries, sends, junk classifications, auth attempts) plus a
// promhttp handler the admin server mounts at /metrics. Uses the standard
// Prometheus client library.
package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// InboundDelivered counts messages accepted and delivered to a mailbox,
	// labeled by mailbox (inbox|junk).
	InboundDelivered = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "octo_mail_inbound_delivered_total",
		Help: "Messages delivered to a local mailbox.",
	}, []string{"mailbox"})

	// InboundRejected counts messages rejected at SMTP time, labeled by reason.
	InboundRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "octo_mail_inbound_rejected_total",
		Help: "Inbound messages rejected, by reason.",
	}, []string{"reason"})

	// OutboundSent counts outbound deliveries, labeled by result (ok|error).
	OutboundSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "octo_mail_outbound_sent_total",
		Help: "Outbound delivery attempts, by result.",
	}, []string{"result"})

	// AuthAttempts counts authentication attempts, labeled by result.
	AuthAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "octo_mail_auth_attempts_total",
		Help: "Authentication attempts, by result (ok|fail|ratelimited).",
	}, []string{"result"})

	// QueueDeliveryDuration is the wall-clock duration of each outbound delivery
	// attempt, labeled by result (ok|error). Mirrors mox's
	// mox_queue_delivery_duration_seconds.
	QueueDeliveryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "octo_mail_queue_delivery_duration_seconds",
		Help:    "Outbound delivery attempt duration, by result.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 20, 30, 60, 120},
	}, []string{"result"})

	// QueueDepth is the number of messages in the outbound queue, labeled by state
	// (due|held|total). Set periodically by the queue depth sampler. Mirrors mox's
	// mox_queue_hold gauge, generalized to the whole queue.
	QueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "octo_mail_queue_depth",
		Help: "Outbound queue depth, by state (due|held|total).",
	}, []string{"state"})
)

// Handler returns the Prometheus metrics HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
