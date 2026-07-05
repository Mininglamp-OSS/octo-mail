#!/bin/sh
# Run the octo-mail DANE-over-real-DNSSEC test (mailflow/deliverability, gated by
# OCTO_MAIL_DANE_DNSSEC=1) inside a Linux container with a genuine DNSSEC chain.
#
# Topology (all in one container):
#   - nsd: authoritative for two zones —
#       example.test : DNSSEC-signed (ECDSA KSK/ZSK) with MX + _25._tcp TLSA.
#       bogus.test   : unsigned.
#   - unbound: VALIDATING recursive resolver on 127.0.0.1:53 with example.test's
#       KSK as a trust anchor; stub-zones forward both zones to nsd. It validates
#       the signed answers (sets the AD bit) and marks bogus.test insecure.
#   - /etc/resolv.conf → 127.0.0.1, so octo-mail's adns resolver trusts the AD bit
#       (loopback rule) and reports Authentic accordingly.
#
# The test then proves deliverability.Lookup returns TLSA records only for the
# authentic (signed) zone — the real-DNSSEC authentic gate, no MockResolver.
#
# octo-mail depends on ../mox via `replace`, so both dirs are mounted.
#
# Usage: scripts/dane-dnssec.sh
set -e

OCTO_MAIL_DIR=$(cd "$(dirname "$0")/.." && pwd)
PARENT=$(dirname "$OCTO_MAIL_DIR")
OCTO_MAIL_NAME=$(basename "$OCTO_MAIL_DIR")

if [ ! -d "$PARENT/mox" ]; then
	echo "expected ../mox next to $OCTO_MAIL_DIR (the replace target)" >&2
	exit 1
fi

docker run --rm \
	-v "$PARENT:/work" \
	-e OCTO_MAIL_DANE_DNSSEC=1 \
	golang:1.25 \
	bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq nsd unbound ldnsutils dnsutils >/dev/null

Z=/zone; mkdir -p "$Z" /run/nsd; cd "$Z"

# --- Signed zone example.test (MX + TLSA) ---
cat > example.test.zone <<EOF
\$ORIGIN example.test.
\$TTL 3600
@   IN SOA ns admin 1 3600 600 86400 3600
@   IN NS  ns
ns  IN A   127.0.0.1
mx  IN A   127.0.0.1
_25._tcp.mx IN TLSA 3 1 1 0000000000000000000000000000000000000000000000000000000000000001
EOF
KSK=$(ldns-keygen -a ECDSAP256SHA256 -k example.test)
ZSK=$(ldns-keygen -a ECDSAP256SHA256 example.test)
ldns-signzone example.test.zone "$ZSK" "$KSK"
grep -h DNSKEY "$KSK.key" > anchor.key   # trust anchor = the KSK DNSKEY

# --- Unsigned zone bogus.test ---
cat > bogus.test.zone <<EOF
\$ORIGIN bogus.test.
\$TTL 3600
@   IN SOA ns admin 1 3600 600 86400 3600
@   IN NS  ns
ns  IN A   127.0.0.1
mx  IN A   127.0.0.1
_25._tcp.mx IN TLSA 3 1 1 0000000000000000000000000000000000000000000000000000000000000002
EOF

# --- nsd: authoritative for both zones ---
cat > /etc/nsd/nsd.conf <<EOF
server:
  interface: 127.0.0.1
  port: 5354
  zonesdir: "$Z"
  pidfile: "/run/nsd/nsd.pid"
zone:
  name: example.test
  zonefile: example.test.zone.signed
zone:
  name: bogus.test
  zonefile: bogus.test.zone
EOF
nsd -c /etc/nsd/nsd.conf -d >/tmp/nsd.log 2>&1 &
sleep 1

# --- unbound: validating resolver, stubs both zones to nsd ---
cat > /etc/unbound/unbound.conf <<EOF
server:
  interface: 127.0.0.1
  port: 53
  do-ip6: no
  access-control: 127.0.0.0/8 allow
  module-config: "validator iterator"
  trust-anchor-file: "$Z/anchor.key"
  local-zone: "test." nodefault
  domain-insecure: "bogus.test."
  harden-dnssec-stripped: no
  root-hints: ""
  do-not-query-localhost: no
stub-zone:
  name: "example.test."
  stub-host: ns.example.test.
  stub-addr: 127.0.0.1@5354
stub-zone:
  name: "bogus.test."
  stub-host: ns.bogus.test.
  stub-addr: 127.0.0.1@5354
EOF
unbound-checkconf /etc/unbound/unbound.conf >/dev/null
unbound -d >/tmp/unbound.log 2>&1 &
sleep 2

# Point the stub resolver at our validating unbound (loopback → adns trusts AD).
echo "nameserver 127.0.0.1" > /etc/resolv.conf

echo "--- dig sanity (example.test must have ad; bogus.test must not) ---"
dig @127.0.0.1 _25._tcp.mx.example.test TLSA +dnssec | grep "^;;" | grep flags
dig @127.0.0.1 _25._tcp.mx.bogus.test  TLSA +dnssec | grep "^;;" | grep flags

echo "--- go test ---"
cd "/work/'"$OCTO_MAIL_NAME"'"
go test -count=1 -run TestDANEOverRealDNSSEC -v ./mailflow/deliverability/
'
