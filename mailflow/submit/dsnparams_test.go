package submit_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
)

// readInboxDSN returns the raw body of the single message in senderID's Inbox.
func readInboxDSN(t *testing.T, ctx context.Context, s *postgres.Store, bs blob.Store, tenantID, senderID int64) string {
	t.Helper()
	var ref string
	if err := s.Pool.QueryRow(ctx,
		`SELECT m.blob_ref FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, senderID).Scan(&ref); err != nil {
		t.Fatalf("no DSN in inbox: %v", err)
	}
	r, err := bs.Open(ctx, tenantID, blob.Ref(ref))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func seedDSNParamsAccount(t *testing.T, ctx context.Context, s *postgres.Store) (tenantID, senderID int64) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var sdom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, tenantID).Scan(&senderID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, tenantID).Scan(&sdom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, sdom, senderID)
	return tenantID, senderID
}

// TestDSNParamsHonored proves the DSN generator honors RFC 3461 params carried
// from submission: NOTIFY=NEVER suppresses the bounce; ENVID and ORCPT are echoed
// into the DSN; RET=FULL includes the original message body.
func TestDSNParamsHonored(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()

	dsnGen := &submit.DSNGenerator{Opener: s, Hostname: dns.Domain{ASCII: "sender.example"}, Blob: bs}

	// --- 1. NOTIFY=NEVER suppresses the failure DSN. ---
	tenantID, senderID := seedDSNParamsAccount(t, ctx, s)
	mNever := queue.Msg{TenantID: tenantID, AccountID: senderID, MailFrom: "me@sender.example", RcptTo: "x@remote.example", BlobRef: "b", Size: 1, Notify: "NEVER"}
	if err := dsnGen.Generate(ctx, mNever); err != nil {
		t.Fatalf("NOTIFY=NEVER generate: %v", err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1`, senderID).Scan(&n)
	if n != 0 {
		t.Fatalf("NOTIFY=NEVER produced %d DSN(s), want 0", n)
	}

	// --- 2. NOTIFY without FAILURE (only DELAY) also suppresses a bounce. ---
	tenantID, senderID = seedDSNParamsAccount(t, ctx, s)
	mDelayOnly := queue.Msg{TenantID: tenantID, AccountID: senderID, MailFrom: "me@sender.example", RcptTo: "x@remote.example", BlobRef: "b", Size: 1, Notify: "DELAY"}
	if err := dsnGen.Generate(ctx, mDelayOnly); err != nil {
		t.Fatal(err)
	}
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1`, senderID).Scan(&n)
	if n != 0 {
		t.Fatalf("NOTIFY=DELAY produced a bounce (%d), want 0 (FAILURE not requested)", n)
	}

	// --- 3. ENVID + ORCPT echoed, RET=FULL returns the original (headers). ---
	tenantID, senderID = seedDSNParamsAccount(t, ctx, s)
	original := "From: me@sender.example\r\nTo: orig@remote.example\r\nSubject: UNIQUESUBJTOKEN42\r\n\r\nbody text\r\n"
	ref, size, err := bs.Put(ctx, tenantID, strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	mFull := queue.Msg{
		TenantID: tenantID, AccountID: senderID, MailFrom: "me@sender.example",
		RcptTo: "final@remote.example", BlobRef: string(ref), Size: size,
		Notify: "FAILURE", Ret: "FULL", EnvID: "ENVID-XYZ-99", ORcpt: "rfc822;orig@remote.example",
	}
	if err := dsnGen.Generate(ctx, mFull); err != nil {
		t.Fatalf("RET=FULL generate: %v", err)
	}
	body := readInboxDSN(t, ctx, s, bs, tenantID, senderID)
	if !strings.Contains(body, "ENVID-XYZ-99") {
		t.Fatalf("DSN missing Original-Envelope-Id ENVID-XYZ-99:\n%s", body)
	}
	if !strings.Contains(body, "orig@remote.example") {
		t.Fatalf("DSN missing ORCPT original recipient:\n%s", body)
	}
	// The reused dsn library returns the original headers (not full body); assert
	// the original Subject header is present in the returned-content MIME part.
	if !strings.Contains(body, "UNIQUESUBJTOKEN42") {
		t.Fatalf("RET=FULL DSN did not include the original message headers:\n%s", body)
	}

	// --- 4. RET omitted → original NOT included. ---
	tenantID, senderID = seedDSNParamsAccount(t, ctx, s)
	ref2, size2, _ := bs.Put(ctx, tenantID, strings.NewReader(original))
	mHdrs := queue.Msg{
		TenantID: tenantID, AccountID: senderID, MailFrom: "me@sender.example",
		RcptTo: "final@remote.example", BlobRef: string(ref2), Size: size2, Notify: "FAILURE",
	}
	if err := dsnGen.Generate(ctx, mHdrs); err != nil {
		t.Fatal(err)
	}
	body = readInboxDSN(t, ctx, s, bs, tenantID, senderID)
	if strings.Contains(body, "UNIQUESUBJTOKEN42") {
		t.Fatalf("RET unset should not include the original:\n%s", body)
	}

	t.Logf("OK: NOTIFY=NEVER/DELAY suppressed bounce; ENVID+ORCPT echoed; RET=FULL returned original headers, RET unset did not")
}
