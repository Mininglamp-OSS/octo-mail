package smtpd_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestSubmissionSenderOwnership proves the H1 fix: an authenticated submission
// client may only use a MAIL FROM address that belongs to its own account. A
// foreign sender (another account, or an external domain) is rejected 550,
// while the account's own address is accepted — closing the sender-spoofing gap.
func TestSubmissionSenderOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, aliceID, bobID, dom int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'alice') RETURNING id`, tenantID).Scan(&aliceID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'bob') RETURNING id`, tenantID).Scan(&bobID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'acme.example') RETURNING id`, tenantID).Scan(&dom)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'alice')`, tenantID, dom, aliceID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'bob')`, tenantID, dom, bobID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'alice@acme.example')`, tenantID)

	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "alice@acme.example", "pw"); err != nil {
		t.Fatal(err)
	}

	subSrv := &smtpd.Server{Dir: dir, Hostname: "mail.acme.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cli, srv := net.Pipe()
	go func() { _ = subSrv.Serve(ctx, srv) }()
	_ = cli.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(cli)

	readCode := func() string {
		line, _ := br.ReadString('\n')
		return strings.TrimSpace(line)
	}
	cmd := func(line string) string {
		cli.Write([]byte(line + "\r\n"))
		return readCode()
	}

	readCode() // greeting
	// EHLO: drain the multiline 250- response until the final "250 " line.
	cli.Write([]byte("EHLO client\r\n"))
	for {
		line, _ := br.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	// AUTH PLAIN as alice.
	tok := base64.StdEncoding.EncodeToString([]byte("alice@acme.example\x00alice@acme.example\x00pw"))
	if r := cmd("AUTH PLAIN " + tok); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: got %q, want 235", r)
	}

	// Alice's own address → accepted.
	if r := cmd("MAIL FROM:<alice@acme.example>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("owned MAIL FROM: got %q, want 250", r)
	}
	cmd("RSET")

	// Another account in the same tenant → rejected.
	if r := cmd("MAIL FROM:<bob@acme.example>"); !strings.HasPrefix(r, "550") {
		t.Fatalf("foreign (same-tenant) MAIL FROM: got %q, want 550", r)
	}

	// An external domain the account doesn't own → rejected.
	if r := cmd("MAIL FROM:<ceo@victim.example>"); !strings.HasPrefix(r, "550") {
		t.Fatalf("spoofed external MAIL FROM: got %q, want 550", r)
	}

	// --- Sequencing bypass (PR #26 review): MAIL FROM before AUTH must not
	// survive a later AUTH. Fresh connection. ---
	cli2, srv2 := net.Pipe()
	go func() { _ = subSrv.Serve(ctx, srv2) }()
	_ = cli2.SetDeadline(time.Now().Add(15 * time.Second))
	br2 := bufio.NewReader(cli2)
	rd2 := func() string { line, _ := br2.ReadString('\n'); return strings.TrimSpace(line) }
	cmd2 := func(line string) string { cli2.Write([]byte(line + "\r\n")); return rd2() }

	rd2() // greeting
	cli2.Write([]byte("EHLO client\r\n"))
	for {
		line, _ := br2.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	// Pre-auth MAIL FROM with a spoofed sender must be rejected outright
	// (submission requires AUTH first).
	if r := cmd2("MAIL FROM:<ceo@victim.example>"); !strings.HasPrefix(r, "530") {
		t.Fatalf("pre-auth MAIL FROM: got %q, want 530 (auth required)", r)
	}
	// Authenticate as alice.
	if r := cmd2("AUTH PLAIN " + tok); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH (seq test): got %q, want 235", r)
	}
	// The spoofed transaction must not have survived: RCPT with no valid MAIL
	// must be refused, proving c.mailFrom was cleared.
	if r := cmd2("RCPT TO:<target@remote.example>"); !strings.HasPrefix(r, "503") {
		t.Fatalf("RCPT after pre-auth-spoof+AUTH: got %q, want 503 (need MAIL first)", r)
	}
	// And a fresh MAIL as the spoofed sender is still rejected on ownership.
	if r := cmd2("MAIL FROM:<ceo@victim.example>"); !strings.HasPrefix(r, "550") {
		t.Fatalf("post-auth spoofed MAIL FROM: got %q, want 550", r)
	}

	t.Logf("OK: submission MAIL FROM ownership enforced — own address 250, foreign/spoofed 550")
}
