//go:build unix

package privsep_test

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/security/privsep"
)

// TestPrivsepRootDrop exercises the real privilege-separation syscall path: as
// root, bind a privileged port, drop to an unprivileged uid, and prove (a) the
// drop took effect, (b) it is irreversible (cannot re-elevate to root), and
// (c) the process still owns and serves the privileged socket bound before the
// drop. This closes the boundary the unit tests could only assert logically.
//
// Gated by OCTO_MAIL_PRIVSEP=1 and requires root (scripts/privsep-root.sh runs it in
// a root container). Skipped otherwise.
func TestPrivsepRootDrop(t *testing.T) {
	if os.Getenv("OCTO_MAIL_PRIVSEP") != "1" {
		t.Skip("privsep root test requires OCTO_MAIL_PRIVSEP=1 and root (scripts/privsep-root.sh)")
	}
	if syscall.Getuid() != 0 {
		t.Fatalf("must run as root (uid=%d); use scripts/privsep-root.sh", syscall.Getuid())
	}

	const target = 65534 // "nobody" on most systems
	// Bind a privileged port (443) while root — only root may bind < 1024.
	lns, err := privsep.BindListeners(map[string]string{"https": "0.0.0.0:443"})
	if err != nil {
		t.Fatalf("bind privileged :443 as root: %v", err)
	}
	ln := lns["https"]
	defer ln.Close()

	// Serve on the pre-bound privileged socket.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			_ = c.Close()
		}
	}()

	// Drop to the unprivileged uid/gid.
	if err := privsep.DropPrivileges(privsep.Ids{UID: target, GID: target}); err != nil {
		t.Fatalf("DropPrivileges: %v", err)
	}

	// (a) The drop took effect.
	if uid := syscall.Getuid(); uid != target {
		t.Fatalf("after drop uid=%d, want %d", uid, target)
	}
	if gid := syscall.Getgid(); gid != target {
		t.Fatalf("after drop gid=%d, want %d", gid, target)
	}

	// (b) The drop is irreversible: re-elevating to root must fail.
	if err := syscall.Setuid(0); err == nil {
		t.Fatalf("setuid(0) succeeded after drop — privilege drop is not irreversible!")
	}

	// (c) The privileged socket bound before the drop still serves, now that the
	// process is unprivileged.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dial pre-bound :443 after drop: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 2)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read from pre-bound :443 after drop: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("privileged socket served %q, want \"ok\"", buf)
	}

	// After dropping uid, a fresh bind of a privileged port should normally fail.
	// This depends on the process's capability set (e.g. a container that grants
	// CAP_NET_BIND_SERVICE keeps the ability even as non-root), so it is an
	// observation, not a hard assertion: the security guarantee that matters is
	// that we CAN pre-bind before dropping (proven above), not that a later bind
	// is denied.
	if l, err := net.Listen("tcp", "0.0.0.0:444"); err == nil {
		_ = l.Close()
		t.Logf("note: privileged :444 still bindable after drop (CAP_NET_BIND_SERVICE retained in this environment)")
	} else {
		t.Logf("fresh privileged bind denied after drop (capability lost, as expected on a stock host)")
	}

	t.Logf("OK: bound :443 as root → dropped to uid=%d (irreversible) → pre-bound privileged socket still serves", target)
}
