package webadmin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/ops/obs"
	"github.com/Mininglamp-OSS/octo-mail/ops/webadmin"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

const dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// TestAdminProvisionEndToEnd proves WF-F: the admin HTTP API provisions a whole
// tenant → domain → account → address → password, and the provisioned account
// can then authenticate over real IMAP. Also exercises /healthz and the webhook
// delivery worker against an httptest sink.
func TestAdminProvisionEndToEnd(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, dsn, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, webhook_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	admin := &webadmin.Server{Pool: s.Pool, Dir: s.NewDirectory(), AdminToken: "secret-admin"}
	hs := httptest.NewServer(admin.Handler())
	defer hs.Close()

	post := func(path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", hs.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer secret-admin")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("POST %s status %d", path, resp.StatusCode)
		}
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m
	}

	// Unauthorized without token.
	{
		resp, _ := http.Post(hs.URL+"/admin/tenants", "application/json", bytes.NewReader([]byte(`{"name":"x"}`)))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("admin without token: status %d, want 401", resp.StatusCode)
		}
	}

	// Provision.
	tid := int64(post("/admin/tenants", map[string]any{"name": "acme"})["id"].(float64))
	post("/admin/accounts", map[string]any{"tenant_id": tid, "name": "u1"})
	post("/admin/domains", map[string]any{"tenant_id": tid, "domain": "example.com"})
	post("/admin/addresses", map[string]any{"tenant_id": tid, "domain": "example.com", "localpart": "u1", "account": "u1"})
	post("/admin/password", map[string]any{"login": "u1@example.com", "password": "s3cret"})

	// The provisioned account can authenticate over real IMAP.
	imap := &imapd.Server{Dir: s.NewDirectory()}
	cc, sc := net.Pipe()
	go func() { _ = imap.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(10 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "s3cret"); err != nil {
		t.Fatalf("provisioned account IMAP login failed: %v", err)
	}

	// /healthz works (no auth).
	hz, err := http.Get(hs.URL + "/healthz")
	if err != nil || hz.StatusCode != 200 {
		t.Fatalf("healthz: err=%v status=%v", err, hz)
	}

	// Webhook worker delivers a queued event to an httptest sink.
	received := make(chan string, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Octo-Mail-Event")
		w.WriteHeader(200)
	}))
	defer sink.Close()
	wh := &deliverability.Webhooks{Pool: s.Pool}
	if err := wh.Enqueue(ctx, tid, 1, sink.URL, "delivered", map[string]any{"rcpt": "bob@remote.example"}); err != nil {
		t.Fatal(err)
	}
	worker := &deliverability.WebhookWorker{Pool: s.Pool, NodeID: "n1"}
	n, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("webhook worker: %v", err)
	}
	if n != 1 {
		t.Fatalf("webhook worker delivered %d, want 1", n)
	}
	select {
	case ev := <-received:
		if ev != "delivered" {
			t.Fatalf("webhook event header = %q, want delivered", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook sink never received POST")
	}

	t.Logf("OK: admin API provisioned tenant→domain→account→address→password; provisioned account logged in via real IMAP; healthz ok; webhook worker delivered event")
}

func TestMetricsEndpoint(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, dsn, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()

	// Increment a counter, then scrape /metrics and assert it appears.
	obs.OutboundSent.WithLabelValues("ok").Inc()

	admin := &webadmin.Server{Pool: s.Pool, Dir: s.NewDirectory(), AdminToken: "x"}
	hs := httptest.NewServer(admin.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/metrics")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("/metrics: err=%v status=%v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("octo_mail_outbound_sent_total")) {
		t.Fatalf("/metrics did not expose octo_mail_outbound_sent_total")
	}
	t.Logf("OK: Prometheus /metrics exposes octo-mail counters")
}
