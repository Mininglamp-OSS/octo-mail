// Package privsep implements privilege separation for octo-mail: bind privileged
// ports (25/465/587/993) while running as root, then irreversibly drop to an
// unprivileged uid/gid before serving any client. This is the octo-mail counterpart
// of the root→unprivileged-user fork+exec, done in-process by pre-binding listeners and
// then setgid/setuid.
//
// Honest boundary: DropPrivileges only has an effect when the process starts as
// root. The pure logic is unit-tested (ResolveUser; the bind-before-drop
// invariant in BindListeners + Sequence). The real setuid/setgid syscall path is
// exercised by TestPrivsepRootDrop (gated by OCTO_MAIL_PRIVSEP=1, run via
// scripts/privsep-root.sh in a root container): it binds a privileged port as
// root, drops to an unprivileged uid, and verifies the drop took effect, is
// irreversible, the pre-bound privileged socket still serves, and a fresh
// privileged bind is then denied.
package privsep

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
)

// Ids holds the resolved numeric uid/gid to drop to.
type Ids struct {
	UID int
	GID int
}

// ResolveUser resolves a target user spec — a username ("mail"), a numeric uid
// ("1000"), or "uid:gid" ("1000:1000") — to numeric ids. A bare username/uid
// uses the user's primary group.
func ResolveUser(spec string) (Ids, error) {
	if spec == "" {
		return Ids{}, fmt.Errorf("empty user spec")
	}
	// "uid:gid" explicit form.
	if u, g, ok := strings.Cut(spec, ":"); ok {
		uid, err1 := strconv.Atoi(u)
		gid, err2 := strconv.Atoi(g)
		if err1 != nil || err2 != nil {
			return Ids{}, fmt.Errorf("invalid uid:gid %q", spec)
		}
		return Ids{UID: uid, GID: gid}, nil
	}
	// Numeric uid: default gid to uid (common in containers), overridden by the
	// user's primary group when the uid resolves.
	if uid, err := strconv.Atoi(spec); err == nil {
		gid := uid
		if u, e := user.LookupId(spec); e == nil {
			gid, _ = strconv.Atoi(u.Gid)
		}
		return Ids{UID: uid, GID: gid}, nil
	}
	// Username.
	u, err := user.Lookup(spec)
	if err != nil {
		return Ids{}, fmt.Errorf("lookup user %q: %w", spec, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Ids{}, fmt.Errorf("non-numeric uid for %q: %w", spec, err)
	}
	gid, _ := strconv.Atoi(u.Gid)
	return Ids{UID: uid, GID: gid}, nil
}

// BindListeners binds every address up front (while still privileged) and returns
// the listeners keyed by the caller's name. If any bind fails, the already-bound
// listeners are closed and the error is returned — nothing is served under
// partial binding.
func BindListeners(addrs map[string]string) (map[string]net.Listener, error) {
	lns := map[string]net.Listener{}
	for name, addr := range addrs {
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return nil, fmt.Errorf("bind %s (%s): %w", name, addr, err)
		}
		lns[name] = ln
	}
	return lns, nil
}

// Sequence runs the privsep startup: bind all listeners, then drop privileges.
// It guarantees ordering — the drop happens only after every listener is bound,
// so the unprivileged process still owns the privileged sockets. drop is the
// privilege-dropping function (DropPrivileges in production; a spy in tests).
func Sequence(addrs map[string]string, ids Ids, drop func(Ids) error) (map[string]net.Listener, error) {
	lns, err := BindListeners(addrs)
	if err != nil {
		return nil, err
	}
	if err := drop(ids); err != nil {
		for _, l := range lns {
			_ = l.Close()
		}
		return nil, fmt.Errorf("drop privileges: %w", err)
	}
	return lns, nil
}
