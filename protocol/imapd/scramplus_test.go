package imapd_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestSCRAMPlusAndPreview proves two extensions over one encrypted connection:
//  1. AUTH=SCRAM-SHA-256-PLUS — channel binding to the TLS session (RFC 7677/
//     5802/9266), driven by the unmodified imapclient; correct password succeeds,
//     wrong password fails.
//  2. FETCH PREVIEW (RFC 8970) — a short text abstract of a message.
func TestSCRAMPlusAndPreview(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	// Deliver a multipart-ish message with a text body for PREVIEW to extract.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	raw := "From: a@remote.example\r\nSubject: hello\r\n\r\nThis is the body text that the preview should abstract into a short snippet.\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
		t.Fatal(err)
	}

	tlsCfg := selfSignedTLS(t)
	srv := &imapd.Server{Dir: dir, TLSConfig: tlsCfg}

	// SCRAM-SHA-256-PLUS requires a real *tls.Conn on the server side, so use the
	// implicit-TLS listener with a tls.Client wrapping the pipe.
	dialTLS := func() *imapclient.Conn {
		cc, sc := net.Pipe()
		go func() { _ = srv.ServeTLS(ctx, sc) }()
		_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
		tc := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, ServerName: "octo-mail.test"})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
		ic, err := imapclient.New(tc, &imapclient.Opts{Error: func(err error) { panic(err) }})
		if err != nil {
			t.Fatal(err)
		}
		return ic
	}

	// --- 1a. SCRAM-SHA-256-PLUS with the correct password succeeds. ---
	authPlus := func(pass string) (rerr error) {
		defer func() {
			if r := recover(); r != nil {
				rerr = errFromPanic(r)
			}
		}()
		ic := dialTLS()
		defer ic.Close()
		// Confirm the server advertises the -PLUS mechanism over TLS.
		capResp, err := ic.Capability()
		if err != nil {
			return err
		}
		if !strings.Contains(strings.ToUpper(capResp.Result.Text+capString(capResp)), "SCRAM-SHA-256-PLUS") {
			t.Fatalf("server did not advertise AUTH=SCRAM-SHA-256-PLUS over TLS: %+v", capResp)
		}
		_, err = ic.AuthenticateSCRAM("SCRAM-SHA-256-PLUS", sha256.New, "u1@example.com", pass)
		return err
	}
	if err := authPlus("correct-horse"); err != nil {
		t.Fatalf("SCRAM-SHA-256-PLUS with correct password failed: %v", err)
	}

	// --- 1b. SCRAM-SHA-256-PLUS with a wrong password fails. ---
	if err := authPlus("wrong"); err == nil {
		t.Fatalf("SCRAM-SHA-256-PLUS with wrong password succeeded — channel-bound proof broken")
	}

	// --- 2. FETCH PREVIEW returns a text abstract. ---
	ic := dialTLS()
	defer ic.Close()
	if _, err := ic.AuthenticateSCRAM("SCRAM-SHA-256-PLUS", sha256.New, "u1@example.com", "correct-horse"); err != nil {
		t.Fatalf("auth for preview: %v", err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := ic.WriteCommandf("", "uid fetch 1 (PREVIEW)"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatalf("fetch preview: %v", err)
	}
	var preview string
	for _, u := range resp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if p, ok := a.(imapclient.FetchPreview); ok && p.Preview != nil {
					preview = *p.Preview
				}
			}
		}
	}
	if preview == "" {
		t.Fatalf("FETCH PREVIEW returned no preview text (untagged=%+v)", resp.Untagged)
	}
	if !strings.Contains(preview, "body text") {
		t.Fatalf("PREVIEW = %q, want it to abstract the body text", preview)
	}
	if strings.ContainsAny(preview, "\r\n") {
		t.Fatalf("PREVIEW contains raw newlines: %q", preview)
	}

	t.Logf("OK: SCRAM-SHA-256-PLUS (channel-bound) accepted correct / rejected wrong password over TLS; FETCH PREVIEW = %q", preview)
}

// capString concatenates capability names from a CAPABILITY response for a
// simple substring check.
func capString(resp imapclient.Response) string {
	var sb strings.Builder
	for _, u := range resp.Untagged {
		if c, ok := u.(imapclient.UntaggedCapability); ok {
			for _, x := range c {
				sb.WriteString(" ")
				sb.WriteString(string(x))
			}
		}
	}
	return sb.String()
}
