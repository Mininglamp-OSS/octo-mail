package blob_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

// s3TestConfig points at the local MinIO (docker container octo-golden-minio-1,
// host port 29000). Overridable via env for other environments.
func s3TestConfig() blob.S3Config {
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return blob.S3Config{
		Endpoint:  get("OCTO_MAIL_S3_ENDPOINT", "http://localhost:29000"),
		Region:    "us-east-1",
		Bucket:    get("OCTO_MAIL_S3_BUCKET", "octo-mail-test"),
		AccessKey: get("OCTO_MAIL_S3_ACCESS", "octoadmin"),
		SecretKey: get("OCTO_MAIL_S3_SECRET", "70521a1a521a5dfd103ce85fe475d8cc"),
	}
}

// TestS3BlobRoundTrip proves the S3 backend satisfies the same blob.Store
// contract as the fs backend, against a REAL S3 server (MinIO): content-address
// Put with dedup, full Open+Read, ranged ReadAt (IMAP FETCH BODY[]<partial>),
// and Delete. SigV4 signing is exercised on every verb.
func TestS3BlobRoundTrip(t *testing.T) {
	s, err := blob.NewS3(s3TestConfig())
	if err != nil {
		t.Skipf("S3/MinIO not available (%v)", err)
	}
	ctx := context.Background()
	const tenant = int64(42)
	body := []byte("Subject: s3 test\r\n\r\nthe quick brown fox jumps over the lazy dog\r\n")

	// Put returns a content-hash ref and the size.
	ref, n, err := s.Put(ctx, tenant, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n != int64(len(body)) {
		t.Fatalf("put size = %d, want %d", n, len(body))
	}
	if want := blob.HashRef(body); ref != want {
		t.Fatalf("put ref = %s, want content hash %s", ref, want)
	}

	// Dedup: a second Put of the same bytes yields the same ref, no error.
	ref2, _, err := s.Put(ctx, tenant, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("put dedup: %v", err)
	}
	if ref2 != ref {
		t.Fatalf("dedup ref mismatch: %s != %s", ref2, ref)
	}

	// Open + full read returns the exact bytes.
	r, err := s.Open(ctx, tenant, ref)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if r.Size() != int64(len(body)) {
		t.Fatalf("open size = %d, want %d", r.Size(), len(body))
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("read mismatch:\n got %q\nwant %q", got, body)
	}

	// Ranged ReadAt: fetch "quick brown" from the middle (partial FETCH).
	full := string(body)
	idx := strings.Index(full, "quick brown")
	r2, err := s.Open(ctx, tenant, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	buf := make([]byte, len("quick brown"))
	m, err := r2.ReadAt(buf, int64(idx))
	if err != nil && err != io.EOF {
		t.Fatalf("readat: %v", err)
	}
	if string(buf[:m]) != "quick brown" {
		t.Fatalf("ranged read = %q, want %q", string(buf[:m]), "quick brown")
	}

	// Delete removes it; a subsequent Open fails.
	if err := s.Delete(ctx, tenant, ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Open(ctx, tenant, ref); err == nil {
		t.Fatalf("open after delete succeeded; want not-found")
	}

	// Cross-tenant isolation: the same bytes under a different tenant is a
	// different key (content-address is namespaced by tenant).
	otherRef, _, err := s.Put(ctx, int64(99), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("put other tenant: %v", err)
	}
	if _, err := s.Open(ctx, tenant, otherRef); err == nil {
		t.Fatalf("tenant 42 could open tenant 99's blob — cross-tenant leak")
	}
	_ = s.Delete(ctx, int64(99), otherRef)

	t.Logf("OK: S3 (MinIO) Put/dedup/Open/ranged-ReadAt/Delete + per-tenant key isolation, all via real SigV4")
}
