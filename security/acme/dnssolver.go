package acme

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DNSSolver publishes and removes the DNS TXT record that answers an ACME dns-01
// challenge. dns-01 is what makes cluster issuance routing-free: the leader
// publishes _acme-challenge.<host> and the CA validates it over DNS, so no
// inbound challenge connection has to reach any particular node.
type DNSSolver interface {
	// Present publishes a TXT record at fqdn (already including the
	// "_acme-challenge." prefix) with the given value.
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the record published by Present. It is best-effort and
	// always called (deferred) after a challenge attempt.
	CleanUp(ctx context.Context, fqdn, value string) error
}

// webhookSolver is the provider-neutral production DNSSolver: it POSTs the record
// mutation to an operator-run endpoint that maps it onto their DNS provider's API.
// The body is HMAC-SHA256 signed (X-Octo-Signature: sha256=<hex>) with a shared
// secret, mirroring octo-mail's outbound webhook signing
// (mailflow/deliverability/ob_webhookworker.go) so the operator can authenticate
// requests. This keeps the core free of any specific DNS provider dependency.
type webhookSolver struct {
	url    string
	secret []byte
	hc     *http.Client
}

// NewWebhookSolver builds a webhookSolver. A nil/zero http.Client gets a default
// with a bounded timeout.
func NewWebhookSolver(url string, secret []byte, hc *http.Client) DNSSolver {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &webhookSolver{url: url, secret: secret, hc: hc}
}

// dnsWebhookRequest is the JSON body sent to the operator's DNS webhook.
type dnsWebhookRequest struct {
	Op    string `json:"op"`    // "present" | "cleanup"
	FQDN  string `json:"fqdn"`  // record name, e.g. _acme-challenge.mail.example.com
	Value string `json:"value"` // TXT value (the dns-01 key authorization digest)
}

func (s *webhookSolver) Present(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, dnsWebhookRequest{Op: "present", FQDN: fqdn, Value: value})
}

func (s *webhookSolver) CleanUp(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, dnsWebhookRequest{Op: "cleanup", FQDN: fqdn, Value: value})
}

func (s *webhookSolver) post(ctx context.Context, body dnsWebhookRequest) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("acme dns webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("acme dns webhook: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(s.secret) > 0 {
		mac := hmac.New(sha256.New, s.secret)
		mac.Write(buf)
		req.Header.Set("X-Octo-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("acme dns webhook %s: %w", body.Op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("acme dns webhook %s: status %d: %s", body.Op, resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}
