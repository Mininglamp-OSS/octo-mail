#!/bin/sh
# Provision a PostgreSQL primary + SYNCHRONOUS standby pair for the octo-mail
# zero-loss HA test (storage/postgres, gated by OCTO_MAIL_HA_SYNC=1).
#
# The primary runs with synchronous_standby_names='*' and synchronous_commit=on,
# so a COMMIT does not return until the standby has durably received the WAL —
# RPO=0 (zero data loss on primary failure). The test proves both the durability
# (a committed row is on the standby) and the blocking semantics (with the
# standby stopped, a commit blocks waiting for the sync ack).
#
#   primary DSN:  postgres://octo_mail:octo_mail@localhost:55435/octo_mail
#   standby DSN:  postgres://octo_mail:octo_mail@localhost:55436/octo_mail
#
# Usage:
#   scripts/ha-pg.sh up      # start the sync pair
#   scripts/ha-pg.sh stopstandby / startstandby   # toggle standby for blocking test
#   scripts/ha-pg.sh down    # remove
set -e

IMG="postgres:17"
NET="octo-mail-hasync-net"
PRIM="octo-mail-hasync-primary"
STBY="octo-mail-hasync-standby"
PW="octo_mail"

case "${1:-up}" in
up)
	docker network create "$NET" >/dev/null 2>&1 || true

	# --- Primary (started WITHOUT synchronous_commit; a sync standby that does
	# not exist yet would deadlock the entrypoint's own CREATE DATABASE). Sync is
	# enabled after the standby is streaming, below. ---
	docker run -d --name "$PRIM" --network "$NET" \
		-e POSTGRES_PASSWORD="$PW" -e POSTGRES_USER=octo_mail -e POSTGRES_DB=octo_mail \
		-p 55435:5432 "$IMG" \
		-c wal_level=replica -c max_wal_senders=10 -c max_replication_slots=10 >/dev/null
	echo "waiting for primary..."
	ok=0
	for i in $(seq 1 90); do
		if docker exec "$PRIM" psql -U octo_mail -d octo_mail -c 'SELECT 1' >/dev/null 2>&1; then
			ok=$((ok + 1))
			[ "$ok" -ge 3 ] && break
		else
			ok=0
		fi
		sleep 1
	done
	# Replication role + a physical slot + pg_hba for the standby.
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c \
		"CREATE ROLE repl WITH REPLICATION LOGIN PASSWORD 'repl';" >/dev/null
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c \
		"SELECT pg_create_physical_replication_slot('standby1');" >/dev/null
	docker exec "$PRIM" sh -c "echo 'host replication repl all md5' >> /var/lib/postgresql/data/pg_hba.conf"
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c "SELECT pg_reload_conf();" >/dev/null

	# --- Standby: base backup from the primary, then start streaming ---
	docker run -d --name "$STBY" --network "$NET" \
		-e PGPASSWORD=repl -e POSTGRES_PASSWORD="$PW" \
		-p 55436:5432 --entrypoint sh "$IMG" -c '
			rm -rf /var/lib/postgresql/data/* &&
			pg_basebackup -h '"$PRIM"' -p 5432 -U repl -D /var/lib/postgresql/data -Fp -Xs -P -R -S standby1 &&
			chmod 0700 /var/lib/postgresql/data &&
			touch /var/lib/postgresql/data/standby.signal &&
			exec docker-entrypoint.sh postgres' >/dev/null
	echo "waiting for standby to connect (async first)..."
	for i in $(seq 1 60); do
		n=$(docker exec "$PRIM" psql -U octo_mail -d octo_mail -tAc \
			"SELECT count(*) FROM pg_stat_replication" 2>/dev/null || echo 0)
		[ "$n" -ge 1 ] 2>/dev/null && break
		sleep 1
	done
	# Now that a standby is streaming, enable synchronous replication so commits
	# require the standby's WAL ack (RPO=0). Doing this before the standby exists
	# would deadlock the primary's own startup transactions.
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c \
		"ALTER SYSTEM SET synchronous_standby_names = '*'" >/dev/null
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c \
		"ALTER SYSTEM SET synchronous_commit = 'on'" >/dev/null
	docker exec "$PRIM" psql -U octo_mail -d octo_mail -c "SELECT pg_reload_conf()" >/dev/null
	echo "waiting for sync state..."
	for i in $(seq 1 30); do
		state=$(docker exec "$PRIM" psql -U octo_mail -d octo_mail -tAc \
			"SELECT sync_state FROM pg_stat_replication LIMIT 1" 2>/dev/null || true)
		[ "$state" = "sync" ] && break
		sleep 1
	done
	echo "sync pair up: sync_state=$(docker exec "$PRIM" psql -U octo_mail -d octo_mail -tAc 'SELECT sync_state FROM pg_stat_replication LIMIT 1' 2>/dev/null)"
	echo "run: OCTO_MAIL_HA_SYNC=1 go test -run TestSyncReplicationZeroLoss ./storage/postgres/"
	;;
stopstandby)
	docker stop "$STBY" >/dev/null && echo "standby stopped"
	;;
startstandby)
	docker start "$STBY" >/dev/null && echo "standby started"
	;;
down)
	docker rm -f "$PRIM" "$STBY" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	echo "sync pair down"
	;;
*)
	echo "usage: $0 [up|stopstandby|startstandby|down]" >&2
	exit 1
	;;
esac
