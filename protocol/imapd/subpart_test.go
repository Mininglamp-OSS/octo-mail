package imapd_test

import (
	"context"
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

// TestFetchSubparts proves P1-2: FETCH of numbered MIME sub-parts — BODY[1],
// BODY[2], BODY[1.MIME] — returns the correct part content, driven by an
// unmodified imapclient.
func TestFetchSubparts(t *testing.T) {
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
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// A 2-part multipart/alternative: text/plain + text/html.
	msg := "From: a@remote.example\r\nTo: u1@example.com\r\nSubject: mp\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"BND\"\r\n\r\n" +
		"--BND\r\nContent-Type: text/plain\r\n\r\nplain part body\r\n" +
		"--BND\r\nContent-Type: text/html\r\n\r\n<p>html part body</p>\r\n" +
		"--BND--\r\n"
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(msg)); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
	ic, err := imapclient.New(cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()
	if _, err := ic.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}

	fetchBody := func(cmd string) string {
		if err := ic.WriteCommandf("", "%s", cmd); err != nil {
			t.Fatal(err)
		}
		resp, err := ic.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range resp.Untagged {
			if f, ok := u.(imapclient.UntaggedFetch); ok {
				for _, a := range f.Attrs {
					if b, ok := a.(imapclient.FetchBody); ok {
						return b.Body
					}
				}
			}
		}
		return ""
	}

	if p1 := fetchBody("uid fetch 1 (BODY[1])"); !strings.Contains(p1, "plain part body") || strings.Contains(p1, "html") {
		t.Fatalf("BODY[1] = %q, want plain part body", p1)
	}
	if p2 := fetchBody("uid fetch 1 (BODY[2])"); !strings.Contains(p2, "html part body") || strings.Contains(p2, "plain part") {
		t.Fatalf("BODY[2] = %q, want html part body", p2)
	}
	if mime1 := fetchBody("uid fetch 1 (BODY[1.MIME])"); !strings.Contains(strings.ToLower(mime1), "text/plain") {
		t.Fatalf("BODY[1.MIME] = %q, want text/plain header", mime1)
	}

	t.Logf("OK: FETCH BODY[1]/BODY[2]/BODY[1.MIME] return correct MIME sub-parts via real imapclient")
}
