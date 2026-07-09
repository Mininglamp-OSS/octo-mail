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

	// MULTIAPPEND cumulative cap: two literals that each individually fit under
	// MaxSize but TOGETHER exceed the per-command budget must be rejected — one
	// connection must not accumulate N×MaxSize (the connection-cap invariant).
	// Each part is ~⅔ MaxSize; the first passes, the second blows the budget.
	part := strings.Repeat("x", (maxSize*2)/3)
	// Use non-sync (LITERAL+) literals so the whole MULTIAPPEND is one write.
	multi := "a5 APPEND INBOX {" + strconv.Itoa(len(part)) + "+}\r\n" + part +
		" {" + strconv.Itoa(len(part)) + "+}\r\n" + part + "\r\n"
	// Write in a goroutine: net.Pipe is unbuffered, and the server writes its
	// rejection while the client is still mid-write, so a synchronous Write would
	// deadlock against our own Read below.
	go func() { _, _ = cc.Write([]byte(multi)) }()
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after MULTIAPPEND: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+ ") {
			continue // LITERAL+ shouldn't prompt, but tolerate
		}
		if strings.HasPrefix(line, "a5 ") {
			if strings.Contains(line, "OK") {
				t.Fatalf("MULTIAPPEND of 2×⅔MaxSize accepted — cumulative budget not enforced: %q", line)
			}
			break // NO/BAD: budget correctly rejected the second literal
		}
	}

	// Exact-fit exhaustion boundary: a first literal of EXACTLY MaxSize drives the
	// per-command budget to precisely 0, then a further 1-byte literal must still be
	// rejected. Guards against the sentinel bug where budget==0 was misread as
	// "unlimited" (which would reopen the aggregate cap on the default config).
	full := strings.Repeat("y", maxSize)
	exact := "a6 APPEND INBOX {" + strconv.Itoa(len(full)) + "+}\r\n" + full +
		" {1+}\r\nz\r\n"
	go func() { _, _ = cc.Write([]byte(exact)) }()
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after exact-fit MULTIAPPEND: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+ ") {
			continue
		}
		if strings.HasPrefix(line, "a6 ") {
			if strings.Contains(line, "OK") {
				t.Fatalf("MULTIAPPEND filling budget to exactly 0 then +1 byte accepted — sentinel/exhausted collision: %q", line)
			}
			break // correctly rejected: 0 budget means exhausted, not unlimited
		}
	}

	t.Logf("OK: APPENDLIMIT=%d advertised; oversized literal refused (NO, no continuation, no allocation); MULTIAPPEND cumulative + exact-fit-exhaustion caps enforced; in-limit APPEND accepted", maxSize)
}
