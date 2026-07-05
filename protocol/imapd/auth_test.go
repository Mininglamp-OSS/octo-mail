package imapd_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestAuthCredentialVerification proves the credential-verification boundary is
// closed: the correct password is accepted, a wrong password is rejected, and a
// login for a principal with no credential is rejected. Before WF2, ANY password
// was accepted — this test would have failed.
func TestAuthCredentialVerification(t *testing.T) {
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
	// A second principal deliberately WITHOUT a password set.
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'nopass@example.com')`, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'nopass')`, tenantID, domID, accID)

	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "correct-horse"); err != nil {
		t.Fatal(err)
	}

	srv := &imapd.Server{Dir: dir}

	login := func(user, pass string) (rerr error) {
		defer func() {
			if r := recover(); r != nil {
				rerr = errFromPanic(r)
			}
		}()
		cc, sc := net.Pipe()
		go func() { _ = srv.Serve(ctx, sc) }()
		_ = cc.SetDeadline(time.Now().Add(60 * time.Second))
		ic, err := imapclient.New(cc, &imapclient.Opts{Error: func(err error) { panic(err) }})
		if err != nil {
			return err
		}
		defer ic.Close()
		_, err = ic.Login(user, pass)
		return err
	}

	// Correct password: accepted.
	if err := login("u1@example.com", "correct-horse"); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	// Wrong password: rejected.
	if err := login("u1@example.com", "wrong"); err == nil {
		t.Fatalf("wrong password was ACCEPTED — credential verification broken")
	}
	// Principal with no credential: rejected (can't log in with anything).
	if err := login("nopass@example.com", ""); err == nil {
		t.Fatalf("login to credential-less principal was accepted")
	}
	if err := login("nopass@example.com", "anything"); err == nil {
		t.Fatalf("login to credential-less principal accepted a password")
	}
	// Unknown principal: rejected.
	if err := login("ghost@example.com", "x"); err == nil {
		t.Fatalf("login as unknown principal accepted")
	}
	t.Logf("OK: correct password accepted; wrong/empty/unknown rejected (credential verification enforced)")
}

func errFromPanic(r any) error {
	if e, ok := r.(error); ok {
		return e
	}
	return fmt.Errorf("%v", r)
}
