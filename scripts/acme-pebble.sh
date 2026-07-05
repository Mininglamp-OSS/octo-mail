#!/bin/sh
# Provision a local pebble ACME server for the octo-mail ACME integration test
# (security/acme, gated by OCTO_MAIL_ACME=1).
#
# Pebble is Let's Encrypt's test ACME CA. We run it on the host network together
# with pebble-challtestsrv acting purely as a DNS server that answers every A
# query with 127.0.0.1. The test requests a cert for a multi-label domain
# (autocert rejects single-label names like "localhost"); pebble resolves it via
# challtestsrv to 127.0.0.1 and validates tls-alpn-01 by connecting to
# 127.0.0.1:5001 — where the test serves the challenge config.
#
#   ACME directory:      https://localhost:14000/dir  (cert signed by pebble minica)
#   validation domain:   mail.octo-mail.test  (→ 127.0.0.1 via challtestsrv)
#   tls-alpn-01 port:    5001  (the test binds this)
#   minica CA (to trust): written to OCTO_MAIL_ACME_CA (default /tmp/octo-mail-pebble-minica.pem)
#
# Usage:
#   scripts/acme-pebble.sh up      # start pebble + challtestsrv, print env
#   scripts/acme-pebble.sh down    # stop + remove
set -e

PEBBLE="ghcr.io/letsencrypt/pebble:latest"
CHALL="ghcr.io/letsencrypt/pebble-challtestsrv:latest"
PNAME="octo-mail-pebble"
CNAME="octo-mail-challtestsrv"
CA_OUT="${OCTO_MAIL_ACME_CA:-/tmp/octo-mail-pebble-minica.pem}"
# Host IP the container can reach back to for challenge validation. On Linux with
# --network host, 127.0.0.1 works; on macOS/Windows Docker Desktop the container
# is in a VM that cannot reach host loopback, so use the host LAN IP.
HOST_IP="${OCTO_MAIL_ACME_HOST_IP:-$(ipconfig getifaddr en0 2>/dev/null || hostname -i 2>/dev/null | awk '{print $1}')}"

case "${1:-up}" in
up)
	# challtestsrv: DNS only on :8053 answering every A query with HOST_IP so
	# pebble validates by connecting to the test's listener on the host. AAAA is
	# disabled (empty defaultIPv6) so pebble uses the reachable IPv4, not ::1
	# (which is unreachable from the Docker VM on macOS).
	docker run -d --name "$CNAME" --network host \
		"$CHALL" -defaultIPv4 "$HOST_IP" -defaultIPv6 "" \
		-dnsserver ":8053" -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
	# PEBBLE_VA_NOSLEEP=1: no random 0-15s validation delay.
	# -dnsserver: resolve validation domains via challtestsrv.
	docker run -d --name "$PNAME" --network host \
		-e PEBBLE_VA_NOSLEEP=1 \
		"$PEBBLE" -config /test/config/pebble-config.json -dnsserver 127.0.0.1:8053 >/dev/null
	# Export pebble's minica so the ACME client can trust the directory's HTTPS.
	cid=$(docker create "$PEBBLE")
	docker cp "$cid:/test/certs/pebble.minica.pem" "$CA_OUT" >/dev/null
	docker rm "$cid" >/dev/null
	echo "pebble up: directory=https://localhost:14000/dir  host_ip=$HOST_IP"
	echo "OCTO_MAIL_ACME_CA=$CA_OUT"
	echo "run: OCTO_MAIL_ACME=1 OCTO_MAIL_ACME_CA=$CA_OUT OCTO_MAIL_ACME_HOST_IP=$HOST_IP go test -run TestACMELiveIssuance ./security/acme/"
	;;
down)
	docker rm -f "$PNAME" "$CNAME" >/dev/null 2>&1 || true
	echo "pebble down"
	;;
*)
	echo "usage: $0 [up|down]" >&2
	exit 1
	;;
esac
