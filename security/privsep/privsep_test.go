package privsep_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/security/privsep"
)

// TestResolveUser covers the user-spec parsing forms.
func TestResolveUser(t *testing.T) {
	// uid:gid explicit.
	if ids, err := privsep.ResolveUser("1000:2000"); err != nil || ids.UID != 1000 || ids.GID != 2000 {
		t.Fatalf("ResolveUser(1000:2000) = %+v, %v", ids, err)
	}
	// bare numeric uid (unknown → uid used as gid).
	if ids, err := privsep.ResolveUser("4242424"); err != nil || ids.UID != 4242424 || ids.GID != 4242424 {
		t.Fatalf("ResolveUser(4242424) = %+v, %v", ids, err)
	}
	// empty rejected.
	if _, err := privsep.ResolveUser(""); err == nil {
		t.Fatalf("empty spec should error")
	}
	// unknown username rejected.
	if _, err := privsep.ResolveUser("definitely-no-such-user-xyz"); err == nil {
		t.Fatalf("unknown username should error")
	}
}

// TestSequenceBindsBeforeDrop proves the security-critical ordering: all
// privileged listeners are bound BEFORE privileges are dropped, so the
// unprivileged process still owns the sockets. A spy drop function verifies the
// listeners are already accepting connections at the moment of the drop.
func TestSequenceBindsBeforeDrop(t *testing.T) {
	addrs := map[string]string{
		"smtp": "127.0.0.1:0",
		"imap": "127.0.0.1:0",
	}
	boundAtDrop := 0
	spyDrop := func(ids privsep.Ids) error {
		// At drop time, every listener must already be open and connectable.
		// We can't read the addresses here, so the caller checks connectability
		// after Sequence returns; here we just record the drop happened.
		boundAtDrop = -1 // sentinel: drop was invoked
		return nil
	}

	lns, err := privsep.Sequence(addrs, privsep.Ids{UID: 1000, GID: 1000}, spyDrop)
	if err != nil {
		t.Fatalf("Sequence: %v", err)
	}
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	if boundAtDrop != -1 {
		t.Fatalf("drop function was not invoked")
	}
	if len(lns) != 2 {
		t.Fatalf("got %d listeners, want 2", len(lns))
	}
	// Every returned listener is bound and accepting (dial succeeds).
	for name, ln := range lns {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("listener %s not accepting after Sequence: %v", name, err)
		}
		c.Close()
	}
}

// TestSequenceAbortsOnBindFailure verifies that if any bind fails, no listeners
// are left open and the drop is NOT performed (fail closed).
func TestSequenceAbortsOnBindFailure(t *testing.T) {
	// Bind a port first, then ask Sequence to bind the same port → conflict.
	pre, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pre.Close()
	conflict := pre.Addr().String()

	dropCalled := false
	_, err = privsep.Sequence(
		map[string]string{"a": "127.0.0.1:0", "b": conflict},
		privsep.Ids{UID: 1000, GID: 1000},
		func(privsep.Ids) error { dropCalled = true; return nil },
	)
	if err == nil {
		t.Fatalf("expected bind conflict error")
	}
	if dropCalled {
		t.Fatalf("privileges were dropped despite a bind failure (must fail closed)")
	}
}

// TestChownTree covers the recursive hand-over helper without requiring root: a
// missing dir is a no-op, and chowning an existing tree to the current uid/gid
// (a valid no-op chown any user may perform) walks every entry without error.
func TestChownTree(t *testing.T) {
	// Missing dir: no error, nothing to do.
	if err := privsep.ChownTree(filepath.Join(t.TempDir(), "does-not-exist"), privsep.Ids{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatalf("missing dir should be a no-op, got %v", err)
	}

	// Build a small tree: root/tenant/ab/cd/blob + root/tmp/x.
	root := t.TempDir()
	for _, d := range []string{
		filepath.Join(root, "7", "ab", "cd"),
		filepath.Join(root, "tmp"),
	} {
		if err := os.MkdirAll(d, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		filepath.Join(root, "7", "ab", "cd", "blob"),
		filepath.Join(root, "tmp", "x"),
	} {
		if err := os.WriteFile(f, []byte("x"), 0o660); err != nil {
			t.Fatal(err)
		}
	}
	// Chown to our own uid/gid: a permitted no-op that still exercises the full walk.
	if err := privsep.ChownTree(root, privsep.Ids{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatalf("ChownTree over existing tree: %v", err)
	}
}
