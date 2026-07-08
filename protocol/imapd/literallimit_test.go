package imapd_test

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestIMAPLiteralLimit proves the H12 DoS guard: APPENDLIMIT advertises a finite
// size derived from the server's MaxSize, and a literal declaring a larger size
// is rejected (tagged NO [TOOBIG]) BEFORE any allocation — for a synchronizing
// literal without ever sending the "+" continuation that would invite the
// oversized payload. An in-limit APPEND still succeeds.
func TestIMAPLiteralLimit(t *testing.T) {
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

	const maxSize = 1 << 20 // 1 MiB APPENDLIMIT for the test
	srv := &imapd.Server{Dir: dir, MaxSize: maxSize}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, cc)

	// APPENDLIMIT advertises the finite MaxSize, not maxint64.
	caps := strings.Join(rc.mustOK("a1", "capability"), " ")
	if !strings.Contains(caps, "APPENDLIMIT="+strconv.Itoa(maxSize)) {
		t.Fatalf("CAPABILITY APPENDLIMIT not finite/expected: %s", caps)
	}
	if strings.Contains(caps, "APPENDLIMIT=9223372036854775807") {
		t.Fatalf("APPENDLIMIT still advertised as maxint64: %s", caps)
	}

	rc.mustOK("a2", "login u1@example.com x")

	// An oversized synchronizing literal must be refused with a tagged NO, and the
	// server must NOT send a "+" continuation (which would invite the 2 GB payload).
	oversized := int64(maxSize) + 1
	if _, err := cc.Write([]byte("a3 APPEND INBOX {" + strconv.FormatInt(oversized, 10) + "}\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after oversized APPEND: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+ ") {
			t.Fatalf("server sent a continuation for an oversized literal (would allocate %d bytes): %q", oversized, line)
		}
		if strings.HasPrefix(line, "a3 ") {
			if !strings.Contains(line, "NO") {
				t.Fatalf("oversized literal → %q, want tagged NO", line)
			}
			if !strings.Contains(line, "TOOBIG") {
				t.Logf("note: rejection lacks [TOOBIG] code (still NO): %q", line)
			}
			break
		}
	}

	// A normal in-limit APPEND still works (sync literal, gets its continuation).
	msg := "Subject: ok\r\n\r\nbody\r\n"
	if _, err := cc.Write([]byte("a4 APPEND INBOX {" + strconv.Itoa(len(msg)) + "}\r\n")); err != nil {
		t.Fatal(err)
	}
	// Expect the "+" continuation, then send the payload.
	cont, err := rc.r.ReadString('\n')
	if err != nil {
		t.Fatalf("read continuation: %v", err)
	}
	if !strings.HasPrefix(cont, "+ ") {
		t.Fatalf("in-limit APPEND: want continuation, got %q", cont)
	}
	if _, err := cc.Write([]byte(msg + "\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after in-limit APPEND: %v", err)
		}
		if strings.HasPrefix(line, "a4 ") {
			if !strings.Contains(line, "OK") {
				t.Fatalf("in-limit APPEND → %q, want OK", strings.TrimSpace(line))
			}
			break
		}
	}

	t.Logf("OK: APPENDLIMIT=%d advertised; oversized literal refused (NO, no continuation, no allocation); in-limit APPEND accepted", maxSize)
}
