#!/bin/sh
# Run the octo-mail multi-egress IP test (mailflow/deliverability, gated by
# OCTO_MAIL_EGRESS=1) inside a Linux container, where distinct loopback source IPs
# (127.0.0.2/127.0.0.3) are bindable out of the box (macOS does not alias them).
#
# The IPRouter leases per-tenant source IPs from the pool and SourceIPDialer
# binds each as the outbound socket's local address; the test asserts the peer
# observes the distinct bound IPs.
#
# It uses the shared test Postgres on the host (port 55432), reached from the
# container via host.docker.internal.
#
# octo-mail depends on ../mox via `replace`, so both directories are mounted.
#
# Usage: scripts/egress-linux.sh
set -e

OCTO_MAIL_DIR=$(cd "$(dirname "$0")/.." && pwd)
PARENT=$(dirname "$OCTO_MAIL_DIR")
OCTO_MAIL_NAME=$(basename "$OCTO_MAIL_DIR")

if [ ! -d "$PARENT/mox" ]; then
	echo "expected ../mox next to $OCTO_MAIL_DIR (the replace target)" >&2
	exit 1
fi

docker run --rm \
	--add-host=host.docker.internal:host-gateway \
	-v "$PARENT:/work" \
	-w "/work/$OCTO_MAIL_NAME" \
	-e OCTO_MAIL_EGRESS=1 \
	-e OCTO_MAIL_DSN="postgres://octo_mail:octo_mail@host.docker.internal:55432/octo_mail" \
	golang:1.25 \
	go test -count=1 -run TestEgressDistinctSourceIPs -v ./mailflow/deliverability/
