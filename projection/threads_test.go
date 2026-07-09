package projection_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

func mem(s string) store.BlobReader {
	return &memBlob{data: []byte(s)}
}

type memBlob struct {
	data []byte
	off  int64
}

func (m *memBlob) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *memBlob) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memBlob) Size() int64  { return int64(len(m.data)) }
func (m *memBlob) Close() error { return nil }

// TestThreadingProjectionAndRebuild proves threading is an async, rebuildable
// fold: a reply chain (root + two replies via In-Reply-To/References) collapses
// to a single thread_id, an unrelated message gets its own, and rebuilding from
// zero reproduces the identical grouping.
func TestThreadingProjectionAndRebuild(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID); err != nil {
		t.Fatal(err)
	}
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)

	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}

	// A 3-message conversation, plus one unrelated message.
	root := "Message-ID: <root@example.com>\r\nSubject: hello\r\n\r\nroot body\r\n"
	reply1 := "Message-ID: <r1@example.com>\r\nIn-Reply-To: <root@example.com>\r\nReferences: <root@example.com>\r\nSubject: Re: hello\r\n\r\nreply one\r\n"
	reply2 := "Message-ID: <r2@example.com>\r\nIn-Reply-To: <r1@example.com>\r\nReferences: <root@example.com> <r1@example.com>\r\nSubject: Re: hello\r\n\r\nreply two\r\n"
	unrelated := "Message-ID: <other@example.com>\r\nSubject: different\r\n\r\nnot in thread\r\n"
	for _, raw := range []string{root, reply1, reply2, unrelated} {
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}

	w := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("thread drain: %v", err)
	}

	// The three-message conversation must share one thread_id; unrelated differs.
	threadIDs := func() (conv []int64, other int64) {
		rows, err := s.Pool.Query(ctx, `SELECT id, thread_id FROM messages WHERE account_id=$1 ORDER BY id`, accID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids, threads []int64
		for rows.Next() {
			var id int64
			var th *int64
			if err := rows.Scan(&id, &th); err != nil {
				t.Fatal(err)
			}
			if th == nil {
				t.Fatalf("message %d has NULL thread_id after threading", id)
			}
			ids = append(ids, id)
			threads = append(threads, *th)
		}
		// ids[0..2] are the conversation (delivery order), ids[3] is unrelated.
		return threads[:3], threads[3]
	}
	conv, other := threadIDs()
	if conv[0] != conv[1] || conv[1] != conv[2] {
		t.Fatalf("conversation did not collapse to one thread: %v", conv)
	}
	if other == conv[0] {
		t.Fatalf("unrelated message joined the conversation thread (%d)", other)
	}
	firstThread := conv[0]

	// H13 PR2: the fold also populates the denormalized summary columns from the
	// same parse. Verify subject/preview/summary_folded for the root message.
	checkSummary := func(when string) {
		var subject, preview string
		var folded bool
		if err := s.Pool.QueryRow(ctx,
			`SELECT subject, preview, summary_folded FROM messages WHERE account_id=$1 ORDER BY id LIMIT 1`,
			accID).Scan(&subject, &preview, &folded); err != nil {
			t.Fatal(err)
		}
		if !folded {
			t.Fatalf("%s: root summary_folded=false, want true", when)
		}
		if subject != "hello" {
			t.Fatalf("%s: root subject=%q, want 'hello'", when, subject)
		}
		if !strings.Contains(preview, "root body") {
			t.Fatalf("%s: root preview=%q, want to contain 'root body'", when, preview)
		}
	}
	checkSummary("after fold")

	// Rebuild from zero reproduces the identical grouping.
	if err := w.RebuildAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	conv2, other2 := threadIDs()
	if conv2[0] != conv2[1] || conv2[1] != conv2[2] {
		t.Fatalf("after rebuild, conversation not one thread: %v", conv2)
	}
	if conv2[0] != firstThread {
		t.Fatalf("rebuild produced different thread_id: %d != %d (fold must be deterministic)", conv2[0], firstThread)
	}
	if other2 == conv2[0] {
		t.Fatalf("after rebuild, unrelated joined conversation")
	}
	checkSummary("after rebuild")
	t.Logf("OK: reply chain collapsed to thread %d; unrelated separate; rebuild-from-zero identical; summary columns populated + repopulated", firstThread)
}

// TestFoldPreviewUTF8Safe proves the H13 PR2 fix for the projection-wedge bug: a
// body whose 140-byte cut falls mid-rune must not produce invalid UTF-8, which a
// Postgres text column would reject and stall the fold forever. The preview is
// truncated on a rune boundary and stored without error.
func TestFoldPreviewUTF8Safe(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Body of many 3-byte runes (は = E3 81 AF): the 140th byte lands mid-rune.
	body := strings.Repeat("は", 200)
	raw := "Message-ID: <u@example.com>\r\nSubject: 件名テスト\r\n\r\n" + body + "\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}
	w := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("fold must not error on multibyte body (UTF-8 truncation): %v", err)
	}
	var preview, subject string
	var folded bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT preview, subject, summary_folded FROM messages WHERE account_id=$1 ORDER BY id LIMIT 1`,
		accID).Scan(&preview, &subject, &folded); err != nil {
		t.Fatal(err)
	}
	if !folded {
		t.Fatal("row not folded — fold stalled")
	}
	if !utf8.ValidString(preview) || !utf8.ValidString(subject) {
		t.Fatalf("stored summary is not valid UTF-8: preview=%q subject=%q", preview, subject)
	}
	if len(preview) > 140 {
		t.Fatalf("preview = %d bytes, want <= 140", len(preview))
	}
	if subject != "件名テスト" {
		t.Fatalf("subject = %q, want 件名テスト", subject)
	}
	t.Logf("OK: multibyte body folded without error; preview valid UTF-8 (%d bytes), subject intact", len(preview))
}

// TestFoldPreviewShortInvalidUTF8 guards B1's real trigger: a SHORT (<=140-byte)
// body containing genuinely-invalid UTF-8 (a lone 0xff) — which bypasses the
// mid-rune tail-trim entirely — must still fold without error and store a valid
// UTF-8 preview (else the Postgres text column rejects it and wedges the fold).
func TestFoldPreviewShortInvalidUTF8(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Short body (well under 140 bytes) with a lone 0xff (invalid UTF-8) AND a NUL
	// (0x00 — valid UTF-8 but rejected by Postgres text) in both subject and body,
	// so both hazards are exercised and the tail-trim branch is never reached.
	raw := "Message-ID: <s@example.com>\r\nSubject: bad\xffsub\x00j\r\n\r\nshort\xffbo\x00dy\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
		t.Fatal(err)
	}
	w := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 10}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatalf("fold must not error on short invalid-UTF-8 body: %v", err)
	}
	var preview, subject string
	var folded bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT preview, subject, summary_folded FROM messages WHERE account_id=$1 ORDER BY id LIMIT 1`,
		accID).Scan(&preview, &subject, &folded); err != nil {
		t.Fatal(err)
	}
	if !folded {
		t.Fatal("row not folded — fold stalled on invalid UTF-8")
	}
	if !utf8.ValidString(preview) || !utf8.ValidString(subject) {
		t.Fatalf("stored summary not valid UTF-8: preview=%q subject=%q", preview, subject)
	}
	t.Logf("OK: short invalid-UTF-8 body folded without error; preview/subject stored as valid UTF-8")
}

// TestBackfillSummaries proves B2's fix: rows that were folded before the summary
// columns existed (summary_folded=false, empty search columns, cursor already at
// head) are repopulated by BackfillSummaries — so filtered search finds
// historical mail on an in-place upgrade, without a full rethread/cursor reset.
func TestBackfillSummaries(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, fts, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`).Scan(&tenantID)
	s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID)
	s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Message-ID: <h@example.com>\r\nFrom: Alice Smith <alice@remote.example>\r\nSubject: legacy report\r\n\r\nold body\r\n")); err != nil {
		t.Fatal(err)
	}
	w := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 100}
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-migration state: row was folded for threading but predates
	// the summary columns — thread_id set, cursor at head, summary columns empty
	// and summary_folded=false.
	if _, err := s.Pool.Exec(ctx,
		`UPDATE messages SET summary_folded=false, subject='', from_addr='', to_addrs='', from_search='', to_search='', preview='' WHERE account_id=$1`,
		accID); err != nil {
		t.Fatal(err)
	}

	// The forward drain does NOT fix it (cursor already at head).
	if err := w.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}
	var folded bool
	s.Pool.QueryRow(ctx, `SELECT summary_folded FROM messages WHERE account_id=$1`, accID).Scan(&folded)
	if folded {
		t.Fatal("precondition: forward drain should NOT have re-folded a cursor-passed row")
	}

	// Backfill repopulates it.
	if err := w.BackfillSummaries(ctx, tenantID, accID); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var subject, fromSearch string
	if err := s.Pool.QueryRow(ctx,
		`SELECT subject, from_search, summary_folded FROM messages WHERE account_id=$1`, accID).Scan(&subject, &fromSearch, &folded); err != nil {
		t.Fatal(err)
	}
	if !folded || subject != "legacy report" {
		t.Fatalf("after backfill: folded=%v subject=%q, want true / 'legacy report'", folded, subject)
	}
	if !strings.Contains(strings.ToLower(fromSearch), "alice smith") {
		t.Fatalf("from_search=%q, want to contain display name 'Alice Smith' (search-by-name works post-backfill)", fromSearch)
	}
	// Idempotent: a second backfill is a no-op (nothing left unfolded).
	if err := w.BackfillSummaries(ctx, tenantID, accID); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	t.Logf("OK: legacy folded-but-unbackfilled row repopulated (subject+from_search) by BackfillSummaries; idempotent")
}
