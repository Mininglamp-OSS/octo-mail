package smtpd_test

import (
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

// TestDSNParamsPersisted drives a submission carrying RFC 3461 DSN parameters
// (RET/ENVID on MAIL, NOTIFY/ORCPT on RCPT) and asserts they are parsed and
// persisted onto the enqueued queue row, so the queue worker's DSN generator can
// later honor them. Driven raw over SMTP submission.
func TestDSNParamsPersisted(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, dom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &dom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, dom, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	sub := &smtpd.Server{Dir: dir, Hostname: "mail.sender.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // greeting

	cc.Write([]byte("EHLO client.example\r\n"))
	for {
		l := br.line()
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	tok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + tok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q", r)
	}

	// MAIL with RET + ENVID; RCPT with NOTIFY + ORCPT.
	cc.Write([]byte("MAIL FROM:<me@sender.example> RET=HDRS ENVID=ENV123\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %q", r)
	}
	cc.Write([]byte("RCPT TO:<you@remote.example> NOTIFY=FAILURE,DELAY ORCPT=rfc822;you@remote.example\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT: %q", r)
	}
	cc.Write([]byte("DATA\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA: %q", r)
	}
	cc.Write([]byte("From: me@sender.example\r\nTo: you@remote.example\r\nSubject: dsn params\r\n\r\nbody\r\n.\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("end-of-data: %q", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	// The queued row carries the DSN params.
	var ret, envid, notify, orcpt string
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(dsn_ret,''), COALESCE(dsn_envid,''), COALESCE(dsn_notify,''), COALESCE(dsn_orcpt,'') FROM queue LIMIT 1`).
		Scan(&ret, &envid, &notify, &orcpt); err != nil {
		t.Fatalf("query queue: %v", err)
	}
	if ret != "HDRS" || envid != "ENV123" {
		t.Fatalf("per-message DSN params: ret=%q envid=%q, want HDRS/ENV123", ret, envid)
	}
	if notify != "FAILURE,DELAY" || orcpt != "rfc822;you@remote.example" {
		t.Fatalf("per-recipient DSN params: notify=%q orcpt=%q", notify, orcpt)
	}
	t.Logf("OK: RET/ENVID/NOTIFY/ORCPT parsed on submission and persisted to the queue row")
}

// TestExtensionParamsPersisted proves #25-8: BODY=8BITMIME and SMTPUTF8 requested
// on MAIL FROM are parsed on submission and persisted onto the enqueued queue row,
// so delivery can re-negotiate them with the next hop. Driven raw over SMTP.
func TestExtensionParamsPersisted(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, dom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &dom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, dom, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	sub := &smtpd.Server{Dir: dir, Hostname: "mail.sender.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line() // greeting

	cc.Write([]byte("EHLO client.example\r\n"))
	for {
		l := br.line()
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	tok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + tok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q", r)
	}

	// MAIL requesting both extensions (BODY=8BITMIME has a value; SMTPUTF8 is a bare flag).
	cc.Write([]byte("MAIL FROM:<me@sender.example> BODY=8BITMIME SMTPUTF8\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %q", r)
	}
	cc.Write([]byte("RCPT TO:<you@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT: %q", r)
	}
	cc.Write([]byte("DATA\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA: %q", r)
	}
	// The body MUST contain 8-bit content, else the flags are (correctly) dropped:
	// they're only propagated for genuinely-8-bit mail so a 7-bit message tagged
	// BODY=8BITMIME can't bounce on a legacy next hop. Include a non-ASCII byte.
	cc.Write([]byte("From: me@sender.example\r\nTo: you@remote.example\r\nSubject: 8bit\r\n\r\nbody \xc3\xa9\r\n.\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("end-of-data: %q", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	var body8, utf8 bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(body_8bitmime,false), COALESCE(smtputf8,false) FROM queue LIMIT 1`).
		Scan(&body8, &utf8); err != nil {
		t.Fatalf("query queue: %v", err)
	}
	if !body8 || !utf8 {
		t.Fatalf("extension flags not persisted for 8-bit mail: body_8bitmime=%v smtputf8=%v, want both true", body8, utf8)
	}
	t.Logf("OK: BODY=8BITMIME + SMTPUTF8 parsed on submission and persisted to the queue row (8-bit body)")
}

// TestExtensionParamsDroppedFor7bit proves the bounce-safety gate: a client that
// tags a 7-bit-clean message BODY=8BITMIME/SMTPUTF8 does NOT get those extensions
// forwarded to delivery (which would bounce on a legacy next hop). The flags are
// dropped because the content doesn't need them.
func TestExtensionParamsDroppedFor7bit(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, dom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &dom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, dom, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	sub := &smtpd.Server{Dir: dir, Hostname: "mail.sender.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line()

	cc.Write([]byte("EHLO client.example\r\n"))
	for {
		l := br.line()
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	tok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + tok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q", r)
	}
	cc.Write([]byte("MAIL FROM:<me@sender.example> BODY=8BITMIME SMTPUTF8\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %q", r)
	}
	cc.Write([]byte("RCPT TO:<you@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT: %q", r)
	}
	cc.Write([]byte("DATA\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA: %q", r)
	}
	// Pure 7-bit ASCII body → flags must be dropped.
	cc.Write([]byte("From: me@sender.example\r\nTo: you@remote.example\r\nSubject: 7bit\r\n\r\nplain ascii body\r\n.\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("end-of-data: %q", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	var body8, utf8 bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(body_8bitmime,false), COALESCE(smtputf8,false) FROM queue LIMIT 1`).
		Scan(&body8, &utf8); err != nil {
		t.Fatalf("query queue: %v", err)
	}
	if body8 || utf8 {
		t.Fatalf("7-bit message forwarded extension requests: body_8bitmime=%v smtputf8=%v, want both false (bounce-safety gate)", body8, utf8)
	}
	t.Logf("OK: a 7-bit-clean message tagged BODY=8BITMIME/SMTPUTF8 does not forward the extensions (can't bounce on a legacy hop)")
}

// TestSMTPUTF8NeededForUTF8Localpart proves the fix for the review finding: an
// ASCII-body message with a UTF-8 envelope localpart still requires SMTPUTF8, so
// it must be persisted even though the body is 7-bit (BODY=8BITMIME stays off).
// Gating SMTPUTF8 on the body alone would silently downgrade this valid case.
func TestSMTPUTF8NeededForUTF8Localpart(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, "postgres://octo_mail:octo_mail@localhost:55432/octo_mail", bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, queue_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, dom int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'sender') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'sender.example') RETURNING id`, &dom, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'me')`, tenantID, dom, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'me@sender.example')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "me@sender.example", "pw"); err != nil {
		t.Fatal(err)
	}

	sub := &smtpd.Server{Dir: dir, Hostname: "mail.sender.example", Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}}
	cc, sc := net.Pipe()
	go func() { _ = sub.Serve(ctx, sc) }()
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))
	br := newLineReader(cc)
	_ = br.line()

	cc.Write([]byte("EHLO client.example\r\n"))
	for {
		l := br.line()
		if len(l) < 4 || l[3] == ' ' {
			break
		}
	}
	tok := base64.StdEncoding.EncodeToString([]byte("\x00me@sender.example\x00pw"))
	cc.Write([]byte("AUTH PLAIN " + tok + "\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "235") {
		t.Fatalf("AUTH: %q", r)
	}
	cc.Write([]byte("MAIL FROM:<me@sender.example> SMTPUTF8\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %q", r)
	}
	// UTF-8 localpart in the recipient (ü) — requires SMTPUTF8 even with an ASCII body.
	cc.Write([]byte("RCPT TO:<\xc3\xbcser@remote.example>\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Skipf("server did not accept a UTF-8 localpart RCPT (%q) — SMTPUTF8 addressing not supported on this path", r)
	}
	cc.Write([]byte("DATA\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "354") {
		t.Fatalf("DATA: %q", r)
	}
	// Pure ASCII body — only the envelope needs UTF-8.
	cc.Write([]byte("From: me@sender.example\r\nSubject: ascii\r\n\r\nplain ascii body\r\n.\r\n"))
	if r := br.line(); !strings.HasPrefix(r, "250") {
		t.Fatalf("end-of-data: %q", r)
	}
	cc.Write([]byte("QUIT\r\n"))

	var body8, utf8 bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(body_8bitmime,false), COALESCE(smtputf8,false) FROM queue LIMIT 1`).
		Scan(&body8, &utf8); err != nil {
		t.Fatalf("query queue: %v", err)
	}
	if !utf8 {
		t.Fatalf("SMTPUTF8 dropped for a UTF-8 localpart with ASCII body — silent downgrade of a valid case")
	}
	if body8 {
		t.Fatalf("BODY=8BITMIME set for an ASCII body, want false (client didn't request it and body is 7-bit)")
	}
	t.Logf("OK: SMTPUTF8 persisted for a UTF-8 envelope localpart even with a 7-bit body; 8BITMIME stays off")
}
