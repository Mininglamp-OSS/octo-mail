package imapd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestIMAPParityCaps drives the mox-parity IMAP additions: CREATE-SPECIAL-USE
// (RFC 6154), non-synchronizing literals (LITERAL+, RFC 7888), and the newly
// advertised capabilities (APPENDLIMIT, QUOTA=RES-STORAGE, LITERAL+,
// CREATE-SPECIAL-USE). Driven raw so the special-use LIST flags and the
// non-sync-literal APPEND (no "+ " continuation) are asserted directly.
func TestIMAPParityCaps(t *testing.T) {
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

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, cc)

	// CAPABILITY advertises the parity extensions.
	capUn := rc.mustOK("a1", "capability")
	caps := strings.Join(capUn, " ")
	for _, want := range []string{"CREATE-SPECIAL-USE", "LITERAL+", "APPENDLIMIT=", "QUOTA=RES-STORAGE"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("CAPABILITY missing %s: %s", want, caps)
		}
	}

	rc.mustOK("a2", "login u1@example.com x")

	// CREATE-SPECIAL-USE: create a Sent mailbox with the \Sent attribute.
	rc.mustOK("a3", `create "SentItems" USE (\Sent)`)

	// LIST returns the \Sent special-use flag for it (special-use is always
	// reported; see cmdList).
	un := rc.mustOK("a4", `list "" "*"`)
	sentLine := ""
	for _, l := range un {
		if strings.Contains(l, `"SentItems"`) {
			sentLine = l
		}
	}
	if sentLine == "" {
		t.Fatalf("SentItems not listed: %v", un)
	}
	if !strings.Contains(sentLine, `\Sent`) {
		t.Fatalf("SentItems LIST line missing \\Sent flag: %q", sentLine)
	}

	// Non-synchronizing literal APPEND ({n+}): the whole command is one write and
	// the server must NOT send a "+ " continuation before consuming the literal.
	msg := "Subject: litplus\r\n\r\nbody\r\n"
	appendCmd := "a5 APPEND INBOX {" + itoa(len(msg)) + "+}\r\n" + msg + "\r\n"
	if _, err := cc.Write([]byte(appendCmd)); err != nil {
		t.Fatal(err)
	}
	tagged := readTaggedNoCont(t, rc, "a5")
	if !strings.Contains(tagged, " OK") {
		t.Fatalf("non-sync literal APPEND -> %q, want OK", tagged)
	}

	// GETQUOTAROOT reports the STORAGE resource (QUOTA=RES-STORAGE).
	rc.mustOK("a6", "select INBOX")
	un = rc.mustOK("a7", "getquotaroot INBOX")
	if firstContaining(t, un, "QUOTAROOT") == "" {
		t.Fatalf("no QUOTAROOT response: %v", un)
	}

	t.Logf("OK: CAPABILITY advertises parity caps; CREATE ... USE (\\Sent) → LIST shows \\Sent; non-sync literal APPEND accepted without continuation; QUOTAROOT reported")
}

// readTaggedNoCont reads until the tagged completion, failing if the server sends
// a "+ " continuation (which a non-synchronizing literal must not trigger).
func readTaggedNoCont(t *testing.T, rc *rawIMAP, tag string) string {
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read tag %s: %v", tag, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+ ") {
			t.Fatalf("server sent a continuation for a non-synchronizing literal: %q", line)
		}
		if strings.HasPrefix(line, tag+" ") {
			return line
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
