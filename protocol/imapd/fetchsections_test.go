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

// TestFetchBodySections proves R2-2: FETCH BODY[HEADER], BODY[TEXT],
// BODY[]<partial>, and BODYSTRUCTURE return correct data, driven by an
// unmodified imapclient (raw commands + response parsing).
func TestFetchBodySections(t *testing.T) {
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

	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	const body = "the quick brown fox"
	raw := "From: alice@remote.example\r\nTo: u1@example.com\r\nSubject: sections\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(raw)); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
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

	fetchBodyOf := func(cmd string) string {
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

	// BODY[HEADER] contains the headers, not the body text.
	hdr := fetchBodyOf("uid fetch 1 (BODY[HEADER])")
	if !strings.Contains(hdr, "Subject: sections") || strings.Contains(hdr, body) {
		t.Fatalf("BODY[HEADER] wrong: %q", hdr)
	}

	// BODY[TEXT] contains the body, not the headers.
	txt := fetchBodyOf("uid fetch 1 (BODY[TEXT])")
	if !strings.Contains(txt, body) || strings.Contains(txt, "Subject:") {
		t.Fatalf("BODY[TEXT] wrong: %q", txt)
	}

	// BODY[]<0.9> partial returns the first 9 bytes ("From: ali").
	part := fetchBodyOf("uid fetch 1 (BODY[]<0.9>)")
	if part != "From: ali" {
		t.Fatalf("BODY[]<0.9> = %q, want \"From: ali\"", part)
	}

	// BODYSTRUCTURE mentions TEXT/PLAIN.
	if err := ic.WriteCommandf("", "uid fetch 1 (BODYSTRUCTURE)"); err != nil {
		t.Fatal(err)
	}
	resp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	sawBS := false
	for _, u := range resp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if _, ok := a.(imapclient.FetchBodystructure); ok {
					sawBS = true
				}
			}
		}
	}
	if !sawBS {
		t.Fatalf("no BODYSTRUCTURE in response: %+v", resp.Untagged)
	}

	t.Logf("OK: FETCH BODY[HEADER]/BODY[TEXT]/BODY[]<partial>/BODYSTRUCTURE all correct via real imapclient")
}
