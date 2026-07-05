#!/bin/sh
# Run the octo-mail privsep root test (security/privsep, gated by OCTO_MAIL_PRIVSEP=1)
# inside a root golang container, so the real setuid/setgid syscall path is
# exercised: bind a privileged port as root, drop to an unprivileged uid, and
# verify the pre-bound socket still serves.
#
# octo-mail depends on ../mox via `replace`, so both directories are mounted at the
# same relative layout under /work.
#
# Usage: scripts/privsep-root.sh
set -e

# Repo root (parent of scripts/) and its parent (contains octo-mail + mox).
OCTO_MAIL_DIR=$(cd "$(dirname "$0")/.." && pwd)
PARENT=$(dirname "$OCTO_MAIL_DIR")
OCTO_MAIL_NAME=$(basename "$OCTO_MAIL_DIR")

if [ ! -d "$PARENT/mox" ]; then
	echo "expected ../mox next to $OCTO_MAIL_DIR (the replace target)" >&2
	exit 1
fi

# Run as root (default in the container). Root binds the privileged :443 via its
# CAP_NET_BIND_SERVICE; after setuid to a non-root uid the effective capability
# set is cleared, so a fresh privileged bind is denied — proving pre-binding
# before the drop is necessary.
# --sysctl net.ipv4.ip_unprivileged_port_start=1024: Docker Desktop's Linux VM
# defaults this to 0 (all ports unprivileged), which would mask the privileged-
# port semantics; restore the standard 1024 boundary so the test is meaningful.
docker run --rm \
	--sysctl net.ipv4.ip_unprivileged_port_start=1024 \
	-v "$PARENT:/work" \
	-w "/work/$OCTO_MAIL_NAME" \
	-e OCTO_MAIL_PRIVSEP=1 \
	golang:1.25 \
	go test -count=1 -run TestPrivsepRootDrop -v ./security/privsep/
