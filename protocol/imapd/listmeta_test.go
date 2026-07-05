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
)

// TestListMetadataAndInprogress drives LIST-METADATA (RFC 9590) and INPROGRESS
// (RFC 9585): SETMETADATA then LIST RETURN (METADATA (...)) returns the
// annotation inline as an untagged * METADATA; a large FETCH emits periodic
// * OK [INPROGRESS ("tag" done total)] updates. Driven raw so the untagged lines
// are asserted directly.
func TestListMetadataAndInprogress(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, thread_refs, projection_cursor, annotations RESTART IDENTITY CASCADE`); err != nil {
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

	// Deliver 250 messages so a full FETCH crosses the INPROGRESS threshold (100).
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: m\r\n\r\nx\r\n")); err != nil {
			t.Fatal(err)
		}
	}

	srv := &imapd.Server{Dir: dir}
	cc, sc := net.Pipe()
	go func() { _ = srv.Serve(ctx, sc) }()
	_ = cc.SetDeadline(time.Now().Add(30 * time.Second))
	rc := newRawIMAP(t, cc)

	capUn := rc.mustOK("a1", "capability")
	caps := strings.Join(capUn, " ")
	for _, want := range []string{"LIST-METADATA", "INPROGRESS"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("CAPABILITY missing %s: %s", want, caps)
		}
	}

	rc.mustOK("a2", "login u1@example.com x")

	// Set a server-visible annotation on INBOX, then LIST RETURN (METADATA (...))
	// must return it inline as * METADATA.
	rc.mustOK("a3", `setmetadata INBOX (/private/comment "hello")`)
	un := rc.mustOK("a4", `list "" "INBOX" return (metadata (/private/comment))`)
	metaLine := ""
	for _, l := range un {
		if strings.HasPrefix(l, "* METADATA ") {
			metaLine = l
		}
	}
	if metaLine == "" {
		t.Fatalf("LIST RETURN (METADATA) produced no * METADATA line: %v", un)
	}
	if !strings.Contains(metaLine, "/private/comment") || !strings.Contains(metaLine, "hello") {
		t.Fatalf("* METADATA missing entry/value: %q", metaLine)
	}

	// A large FETCH emits at least one * OK [INPROGRESS ...] update.
	rc.mustOK("a5", "select INBOX")
	un = rc.mustOK("a6", "uid fetch 1:* (FLAGS)")
	sawInprogress := false
	for _, l := range un {
		if strings.Contains(l, "[INPROGRESS (") {
			sawInprogress = true
			if !strings.Contains(l, `"a6"`) {
				t.Fatalf("INPROGRESS missing command tag: %q", l)
			}
		}
	}
	if !sawInprogress {
		t.Fatalf("large FETCH did not emit [INPROGRESS]")
	}

	t.Logf("OK: CAPABILITY has LIST-METADATA+INPROGRESS; LIST RETURN (METADATA) inline * METADATA; large FETCH emits [INPROGRESS]")
}
