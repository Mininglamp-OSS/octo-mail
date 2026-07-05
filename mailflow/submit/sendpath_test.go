package submit_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

const wf6DSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

// captureMX is a trivial SMTP sink that accepts one message and records the DATA
// it received, so the test can assert a DKIM-Signature header was added.
type captureMX struct {
	got chan string
}

func (m *captureMX) serve(nc net.Conn) {
	br := bufio.NewReader(nc)
	bw := nc
	write := func(s string) { bw.Write([]byte(s + "\r\n")) }
	write("220 mx.remote.example ESMTP")
	var inData bool
	var data strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if line == ".\r\n" {
				inData = false
				write("250 2.0.0 accepted")
				select {
				case m.got <- data.String():
				default:
				}
				continue
			}
			data.WriteString(line)
			continue
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			write("250 mx.remote.example")
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			write("250 2.1.0 OK")
		case strings.HasPrefix(up, "DATA"):
			write("354 go ahead")
			inData = true
		case strings.HasPrefix(up, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 OK")
		}
	}
}

// TestSendPathDKIMAndGate proves WF6 wiring: the outbound deliverer (1) blocks a
// send when the reputation gate says the tenant is paused for the remote domain,
// and (2) DKIM-signs with the tenant key so the delivered message carries a
// DKIM-Signature — reputation accrues to the tenant's domain.
func TestSendPathDKIMAndGate(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, wf6DSN)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	// Minimal schema for reputation + dkim.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS reputation_score (tenant_id bigint NOT NULL, remote_domain text NOT NULL, sent bigint NOT NULL DEFAULT 0, complaints bigint NOT NULL DEFAULT 0, bounces bigint NOT NULL DEFAULT 0, paused boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, remote_domain))`,
		`CREATE TABLE IF NOT EXISTS dkim_keys (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, tenant_id bigint NOT NULL, domain text NOT NULL, selector text NOT NULL, algo text NOT NULL DEFAULT 'ed25519', private_key bytea NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE (tenant_id, domain, selector))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE reputation_score, dkim_keys RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}

	const tenant = int64(1)
	bs, _ := blob.NewFS(t.TempDir())
	if _, err := deliverability.GenerateTenantKey(ctx, pool, tenant, "sender.example", "s1"); err != nil {
		t.Fatal(err)
	}
	repo := &deliverability.Service{Pool: pool}
	signer := &deliverability.DKIMSigner{Pool: pool}

	// Blob body for the outbound message.
	raw := "From: me@sender.example\r\nTo: you@remote.example\r\nSubject: gated+signed\r\nDate: Wed, 01 Jul 2026 10:00:00 +0000\r\nMessage-Id: <g1@sender.example>\r\n\r\nhello\r\n"
	ref, size, err := bs.Put(ctx, tenant, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	msg := queue.Msg{TenantID: tenant, AccountID: 1, MailFrom: "me@sender.example", RcptTo: "you@remote.example", BlobRef: string(ref), Size: size}

	mx := &captureMX{got: make(chan string, 1)}
	dialer := func(ctx context.Context, domain string) (net.Conn, dns.Domain, error) {
		c, srv := net.Pipe()
		go mx.serve(srv)
		return c, dns.Domain{ASCII: "mx.remote.example"}, nil
	}
	d := &submit.SMTPDeliverer{
		Blob:         bs,
		Dial:         dialer,
		EHLOHostname: dns.Domain{ASCII: "sender.example"},
		TLSMode:      smtpclient.TLSSkip,
		Gate: func(ctx context.Context, tid int64, dom string) error {
			r, e := repo.Gate(ctx, tid, dom)
			if e != nil {
				return e
			}
			if !r.Allowed {
				return io.EOF // any non-nil error blocks
			}
			return nil
		},
		Sign:       signer.Sign,
		RecordSent: repo.RecordSent,
	}

	// --- 1. Pause the tenant for remote.example: the gate blocks the send. ---
	if _, err := pool.Exec(ctx, `INSERT INTO reputation_score (tenant_id, remote_domain, sent, paused) VALUES ($1,'remote.example',100,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := d.Deliver(ctx, msg); err == nil {
		t.Fatalf("gate did not block a paused tenant's send")
	}

	// --- 2. Un-pause: the send proceeds and carries a DKIM-Signature. ---
	if _, err := pool.Exec(ctx, `UPDATE reputation_score SET paused=false WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := d.Deliver(ctx, msg); err != nil {
		t.Fatalf("deliver after un-pause: %v", err)
	}
	select {
	case got := <-mx.got:
		if !strings.Contains(strings.ToLower(got), "dkim-signature:") {
			t.Fatalf("delivered message has no DKIM-Signature:\n%s", got)
		}
		if !strings.Contains(got, "d=sender.example") {
			t.Fatalf("DKIM signature not attributed to tenant domain sender.example:\n%s", firstLines(got, 6))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MX did not receive the message")
	}
	t.Logf("OK: reputation gate blocked paused tenant; after un-pause the delivered message was DKIM-signed for sender.example")
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
