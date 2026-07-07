package blob

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRefValid checks the canonical content-ref validator: only a 64-char
// lowercase hex string is accepted; anything path-shaped or malformed is not.
func TestRefValid(t *testing.T) {
	good := Ref(strings.Repeat("a", 64))
	if !good.Valid() {
		t.Fatal("canonical 64-hex ref should be valid")
	}
	bad := []Ref{
		"",
		Ref(strings.Repeat("a", 63)),          // too short
		Ref(strings.Repeat("a", 65)),          // too long
		Ref(strings.Repeat("A", 64)),          // uppercase
		"../../../../etc/passwd",              // traversal
		Ref(strings.Repeat("a", 60) + "/../"), // embedded traversal
		Ref(strings.Repeat("g", 64)),          // non-hex
	}
	for _, r := range bad {
		if r.Valid() {
			t.Errorf("ref %q should be invalid", r)
		}
	}
}

// TestFSOpenRejectsTraversal proves the P0 fix (PR #26 review): a crafted,
// non-canonical ref containing "../" is rejected by the store boundary before
// any filesystem access, so it cannot escape the tenant key prefix and read an
// arbitrary file. A planted secret outside the blob root must stay unreadable.
func TestFSOpenRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	// Plant a secret in a sibling dir the traversal would target.
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := NewFS(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A ref engineered to resolve to the planted secret via path traversal.
	rel, err := filepath.Rel(filepath.Join(root, "1", "..", ".."), secret)
	if err != nil {
		t.Fatal(err)
	}
	evil := Ref("../../" + rel) // whatever the shape, it is non-canonical

	if _, err := s.Open(ctx, 1, evil); err != ErrBadRef {
		t.Fatalf("Open(traversal ref) = %v, want ErrBadRef (no file access)", err)
	}
	if err := s.Delete(ctx, 1, evil); err != ErrBadRef {
		t.Fatalf("Delete(traversal ref) = %v, want ErrBadRef", err)
	}

	// Sanity: a real round-trip with a canonical ref still works.
	ref, _, err := s.Put(ctx, 1, strings.NewReader("hello world"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !ref.Valid() {
		t.Fatalf("Put returned non-canonical ref %q", ref)
	}
	rd, err := s.Open(ctx, 1, ref)
	if err != nil {
		t.Fatalf("Open(canonical ref): %v", err)
	}
	rd.Close()
	t.Logf("OK: traversal refs rejected with ErrBadRef; canonical refs round-trip")
}
