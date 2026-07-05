//go:build unix

package privsep

import (
	"fmt"
	"syscall"
)

// DropPrivileges irreversibly drops the process to the given gid then uid
// (order matters: setgid must precede setuid, since after setuid the process may
// lack permission to change groups). No-op-ish when already running as that uid.
// Only effective when the process starts privileged (root); otherwise setuid to
// a different uid returns EPERM, which is surfaced as an error.
func DropPrivileges(ids Ids) error {
	if syscall.Getuid() == ids.UID && syscall.Getgid() == ids.GID {
		return nil // already the target user
	}
	if err := syscall.Setgroups([]int{ids.GID}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(ids.GID); err != nil {
		return fmt.Errorf("setgid(%d): %w", ids.GID, err)
	}
	if err := syscall.Setuid(ids.UID); err != nil {
		return fmt.Errorf("setuid(%d): %w", ids.UID, err)
	}
	// Verify the drop actually took effect (defense-in-depth against a setuid
	// that silently no-ops on some platforms).
	if syscall.Getuid() != ids.UID {
		return fmt.Errorf("setuid did not take effect (uid still %d)", syscall.Getuid())
	}
	return nil
}
