// Package blob stores immutable message bodies, keyed by content hash. The
// default fsStore keeps them on local disk; an S3 implementation lands in a
// later phase behind the same interface. Bodies are content-addressed so
// identical messages (fan-out) dedup for free; dedup is scoped per tenant to
// avoid leaking cross-tenant existence.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Ref is a content-hash reference (hex sha256).
type Ref string

// Store persists and retrieves immutable blobs within a tenant namespace.
type Store interface {
	// Put stores data and returns its content-hash ref. Idempotent: storing the
	// same bytes twice yields the same ref and no duplicate storage.
	Put(ctx context.Context, tenantID int64, r io.Reader) (Ref, int64, error)
	// Open returns a reader for a blob.
	Open(ctx context.Context, tenantID int64, ref Ref) (Reader, error)
	// Delete removes a blob (called by GC at refcount 0).
	Delete(ctx context.Context, tenantID int64, ref Ref) error
}

// Reader streams a blob; supports ranged reads for IMAP FETCH BODY[]<partial>.
type Reader interface {
	io.ReadCloser
	io.ReaderAt
	Size() int64
}

// HashRef computes the content-hash ref for data (used for pre-checks/tests).
func HashRef(data []byte) Ref {
	sum := sha256.Sum256(data)
	return Ref(hex.EncodeToString(sum[:]))
}

// fsStore is a filesystem-backed blob store: <root>/<tenant>/<ab>/<cd>/<hash>.
type fsStore struct{ root string }

// NewFS returns a filesystem blob store rooted at dir.
func NewFS(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return nil, err
	}
	return &fsStore{root: dir}, nil
}

func (s *fsStore) path(tenantID int64, ref Ref) string {
	h := string(ref)
	ab, cd := "00", "00"
	if len(h) >= 4 {
		ab, cd = h[0:2], h[2:4]
	}
	return filepath.Join(s.root, itoa(tenantID), ab, cd, h)
}

func (s *fsStore) Put(ctx context.Context, tenantID int64, r io.Reader) (Ref, int64, error) {
	// Stream to a temp file while hashing, then rename into the content-addressed
	// path. Rename is atomic on the same filesystem; a duplicate put is a no-op.
	tmpDir := filepath.Join(s.root, "tmp")
	if err := os.MkdirAll(tmpDir, 0o770); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(tmpDir, "blob-")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	ref := Ref(hex.EncodeToString(h.Sum(nil)))

	dst := s.path(tenantID, ref)
	if err := os.MkdirAll(filepath.Dir(dst), 0o770); err != nil {
		return "", 0, err
	}
	if _, err := os.Stat(dst); err == nil {
		return ref, n, nil // already stored (dedup)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return "", 0, err
	}
	return ref, n, nil
}

func (s *fsStore) Open(ctx context.Context, tenantID int64, ref Ref) (Reader, error) {
	f, err := os.Open(s.path(tenantID, ref))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &fsReader{File: f, size: fi.Size()}, nil
}

func (s *fsStore) Delete(ctx context.Context, tenantID int64, ref Ref) error {
	err := os.Remove(s.path(tenantID, ref))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type fsReader struct {
	*os.File
	size int64
}

func (r *fsReader) Size() int64 { return r.size }

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
