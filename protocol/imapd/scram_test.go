package imapd_test

import (
	"context"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestSCRAMAuthentication proves the SASL SCRAM-SHA-256 boundary: a real client
// (an unmodified imapclient.AuthenticateSCRAM) authenticates without ever
// sending the password — the server drives the exchange against the stored
// salted verifier. Correct password succeeds; wrong password fails the proof.
func TestSCRAMAuthentication(t *testing.T) {
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

	srv := &imapd.Server{Dir: dir}

	authSCRAM := func(pass string) (rerr error) {
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
		_, err = ic.AuthenticateSCRAM("SCRAM-SHA-256", sha256.New, "u1@example.com", pass)
		return err
	}

	// Correct password: SCRAM proof verifies, login succeeds.
	if err := authSCRAM("correct-horse"); err != nil {
		t.Fatalf("SCRAM with correct password failed: %v", err)
	}
	// Wrong password: proof fails.
	if err := authSCRAM("wrong"); err == nil {
		t.Fatalf("SCRAM with wrong password succeeded — proof verification broken")
	}
	t.Logf("OK: SCRAM-SHA-256 exchange succeeded for correct password, rejected wrong (password never sent)")
}
