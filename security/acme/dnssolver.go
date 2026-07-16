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
	"net"
	"net/http"
	"strconv"
	"time"
)

// DNSSolver publishes and removes the DNS TXT record that answers an ACME dns-01
// challenge. dns-01 is what makes cluster issuance routing-free: the leader
// publishes _acme-challenge.<host> and the CA validates it over DNS, so no
// inbound challenge connection has to reach any particular node.
//
// Propagation contract: Present MUST NOT return until the published TXT record is
// visible to the ACME CA's resolvers — the manager calls Accept immediately after
// Present, so a solver that returns before propagation will fail validation. A
// webhook solver's endpoint is therefore expected to block until the record is
// live (or to front a provider with fast, authoritative propagation). The manager
// gives Present the per-host issue budget (perHostIssueTimeout) via ctx rather
// than a short fixed client timeout, so a solver that legitimately blocks for
// tens of seconds of propagation is not cut off early.
type DNSSolver interface {
	// Present publishes a TXT record at fqdn (already including the
	// "_acme-challenge." prefix) with the given value, returning only once it is
	// resolvable by the CA (see the propagation contract above).
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the record published by Present. It is best-effort and
	// always called (deferred) after a challenge attempt.
	CleanUp(ctx context.Context, fqdn, value string) error
}

// webhookSolver is the provider-neutral production DNSSolver: it POSTs the record
// mutation to an operator-run endpoint that maps it onto their DNS provider's API.
// The body is HMAC-SHA256 signed (X-Octo-Signature: sha256=<hex>) with a shared
// secret, mirroring octo-mail's outbound webhook signing
// (mailflow/deliverability/ob_webhookworker.go). The signed body includes a unix
// timestamp (also sent as X-Octo-Timestamp) so the operator can enforce a skew
// window and reject replays. This keeps the core free of any specific DNS provider
// dependency.
type webhookSolver struct {
	url    string
	secret []byte
	hc     *http.Client
	now    func() time.Time // injectable for tests; nil = time.Now
}

// NewWebhookSolver builds a webhookSolver. A nil http.Client gets an SSRF-hardened
// default (refuses redirects, blocks non-public addresses) with NO fixed timeout —
// the per-request context (the manager's per-host budget) governs deadlines, so a
// solver that blocks for real DNS propagation is not cut off by a short client cap.
func NewWebhookSolver(url string, secret []byte, hc *http.Client) DNSSolver {
	if hc == nil {
		hc = hardenedWebhookClient()
	}
	return &webhookSolver{url: url, secret: secret, hc: hc}
}

// hardenedWebhookClient mirrors the SSRF posture of the outbound webhook client
// (mailflow/deliverability): no redirects, and dial only vetted public addresses.
// No Timeout — the caller's context deadline bounds the request (DNS propagation
// can legitimately take longer than a short fixed timeout).
func hardenedWebhookClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("acme dns webhook: redirects are not followed")
		},
		Transport: &http.Transport{DialContext: safeDialContext},
	}
}

// safeDialContext resolves the target and dials only if a resolved address is a
// public IP; otherwise it refuses (DNS-rebinding-resistant, bound per-connection).
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
			return d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
	}
	return nil, fmt.Errorf("acme dns webhook: refusing to connect to non-public address for host %q", host)
}

// isBlockedIP reports whether ip must never be targeted: loopback, private
// (RFC1918 / ULA), link-local (incl. 169.254.169.254), unspecified, or multicast.
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

// dnsWebhookRequest is the JSON body sent to the operator's DNS webhook.
type dnsWebhookRequest struct {
	Op    string `json:"op"`    // "present" | "cleanup"
	FQDN  string `json:"fqdn"`  // record name, e.g. _acme-challenge.mail.example.com
	Value string `json:"value"` // TXT value (the dns-01 key authorization digest)
	TS    int64  `json:"ts"`    // unix seconds, signed; operator enforces a skew window
}

func (s *webhookSolver) Present(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, "present", fqdn, value)
}

func (s *webhookSolver) CleanUp(ctx context.Context, fqdn, value string) error {
	return s.post(ctx, "cleanup", fqdn, value)
}

func (s *webhookSolver) post(ctx context.Context, op, fqdn, value string) error {
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	body := dnsWebhookRequest{Op: op, FQDN: fqdn, Value: value, TS: nowFn().Unix()}
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
		req.Header.Set("X-Octo-Timestamp", strconv.FormatInt(body.TS, 10))
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("acme dns webhook %s: %w", op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("acme dns webhook %s: status %d: %s", op, resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}
