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

// TestIMAPBreadth drives the WF-D protocol additions with the unmodified
// imapclient: STATUS (counts without select), NAMESPACE, ENABLE, CHECK, and
// CLOSE/UNSELECT. STATUS is verified against a mailbox with a known message
// count.
func TestIMAPBreadth(t *testing.T) {
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

	// Deliver 2 messages to Inbox so STATUS has counts to report.
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: m\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
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
		t.Fatalf("login: %v", err)
	}

	// NAMESPACE.
	nsResp, err := ic.Namespace()
	if err != nil {
		t.Fatalf("NAMESPACE: %v", err)
	}
	sawNS := false
	for _, u := range nsResp.Untagged {
		if _, ok := u.(imapclient.UntaggedNamespace); ok {
			sawNS = true
		}
	}
	if !sawNS {
		t.Fatalf("no NAMESPACE untagged response")
	}

	// STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN) — without selecting.
	stResp, err := ic.Status("INBOX", imapclient.StatusMessages, imapclient.StatusUIDNext, imapclient.StatusUIDValidity, imapclient.StatusUnseen)
	if err != nil {
		t.Fatalf("STATUS: %v", err)
	}
	var got imapclient.UntaggedStatus
	for _, u := range stResp.Untagged {
		if st, ok := u.(imapclient.UntaggedStatus); ok {
			got = st
		}
	}
	if got.Attrs[imapclient.StatusMessages] != 2 {
		t.Fatalf("STATUS MESSAGES = %d, want 2", got.Attrs[imapclient.StatusMessages])
	}
	if got.Attrs[imapclient.StatusUnseen] != 2 {
		t.Fatalf("STATUS UNSEEN = %d, want 2", got.Attrs[imapclient.StatusUnseen])
	}
	if got.Attrs[imapclient.StatusUIDNext] < 3 {
		t.Fatalf("STATUS UIDNEXT = %d, want >= 3", got.Attrs[imapclient.StatusUIDNext])
	}

	// ENABLE CONDSTORE.
	if _, err := ic.Enable(imapclient.CapCondstore); err != nil {
		t.Fatalf("ENABLE: %v", err)
	}

	// SELECT then CHECK then UNSELECT.
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if err := ic.WriteCommandf("", "check"); err != nil {
		t.Fatal(err)
	}
	if resp, err := ic.ReadResponse(); err != nil || !strings.Contains(strings.ToUpper(resp.Result.Text+string(resp.Result.Status)), "OK") {
		t.Fatalf("CHECK: %v resp=%+v", err, resp.Result)
	}
	if _, err := ic.Unselect(); err != nil {
		t.Fatalf("UNSELECT: %v", err)
	}

	// FETCH ENVELOPE returns a real parsed envelope (subject/from), not a stub.
	if _, err := ic.Select("INBOX"); err != nil {
		t.Fatal(err)
	}
	if err := ic.WriteCommandf("", "uid fetch 1 (ENVELOPE)"); err != nil {
		t.Fatal(err)
	}
	envResp, err := ic.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	sawEnv := false
	for _, u := range envResp.Untagged {
		if f, ok := u.(imapclient.UntaggedFetch); ok {
			for _, a := range f.Attrs {
				if e, ok := a.(imapclient.FetchEnvelope); ok {
					sawEnv = true
					if e.Subject != "m" {
						t.Fatalf("ENVELOPE subject = %q, want \"m\"", e.Subject)
					}
				}
			}
		}
	}
	if !sawEnv {
		t.Fatalf("FETCH ENVELOPE returned no envelope")
	}

	t.Logf("OK: NAMESPACE, STATUS(messages=2 unseen=2), ENABLE CONDSTORE, SELECT/CHECK/UNSELECT, real ENVELOPE(subject=m) via real imapclient")
}
