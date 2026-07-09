//go:build unix

package privsep

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ChownTree recursively chowns dir (and everything under it) to ids.UID/ids.GID.
// It must run while still privileged (before DropPrivileges): the fs blob store
// creates its root as root, but tenant/shard subdirs are made lazily at write
// time by the already-dropped unprivileged process — which can't create them
// inside a root-owned tree. Chowning the tree to the target user first lets those
// lazy MkdirAll calls succeed. Uses Lchown so symlinks aren't dereferenced. A
// missing dir is not an error (nothing to hand over yet).
//
// Entries already owned by the target uid/gid are skipped, so a normal restart
// (tree already handed over on a prior boot) does not re-chown every file — only
// the first boot after enabling privsep pays the full walk. This keeps startup
// (which precedes binding the privileged ports) fast on a large existing tree.
func ChownTree(dir string, ids Ids) error {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip entries already owned by the target — avoids re-chowning the whole
		// tree on every restart.
		if info, e := d.Info(); e == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok &&
				int(st.Uid) == ids.UID && int(st.Gid) == ids.GID {
				return nil
			}
		}
		return os.Lchown(path, ids.UID, ids.GID)
	})
}
