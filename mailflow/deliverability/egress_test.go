//go:build unix

package deliverability_test

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/dns"
)

// TestEgressDistinctSourceIPs proves the full multi-egress path end to end: the
// IPRouter leases per-tenant source IPs from the pool, and submit.SourceIPDialer
// binds each as the outbound connection's local address, so the peer observes
// exactly those distinct IPs. This closes the "socket source binding reaches the
// wire from the router" boundary that the unit tests only covered piecewise.
//
// Requires distinct bindable loopback IPs (127.0.0.2/127.0.0.3), which Linux
// provides out of the box but macOS does not — so it is gated by OCTO_MAIL_EGRESS=1
// and run in a Linux container (scripts/egress-linux.sh).
func TestEgressDistinctSourceIPs(t *testing.T) {
	if os.Getenv("OCTO_MAIL_EGRESS") != "1" {
		t.Skip("egress test requires OCTO_MAIL_EGRESS=1 and Linux loopback aliases (scripts/egress-linux.sh)")
	}
	ctx := context.Background()
	dsn := os.Getenv("OCTO_MAIL_DSN")
	if dsn == "" {
		dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not available (%v)", err)
	}

	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS ip_pools (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, name text NOT NULL UNIQUE, purpose text NOT NULL DEFAULT 'shared')`,
		`CREATE TABLE IF NOT EXISTS ip_addresses (id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY, pool_id bigint NOT NULL REFERENCES ip_pools(id), ip inet NOT NULL, ptr text, warmup_stage int NOT NULL DEFAULT 0, daily_cap bigint NOT NULL DEFAULT 0, sent_today bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS tenant_ip_assignment (tenant_id bigint NOT NULL, pool_id bigint NOT NULL REFERENCES ip_pools(id), dedicated boolean NOT NULL DEFAULT false, PRIMARY KEY (tenant_id, pool_id))`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `TRUNCATE tenant_ip_assignment, ip_addresses, ip_pools RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	const tenant = int64(1)
	var poolID int64
	if err := pool.QueryRow(ctx, `INSERT INTO ip_pools (name, purpose) VALUES ('egress','dedicated') RETURNING id`).Scan(&poolID); err != nil {
		t.Fatal(err)
	}
	// Two loopback source IPs bindable on Linux. daily_cap 1 each → the router
	// hands out a different IP on each of the two leases (least-loaded ordering).
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		if _, err := pool.Exec(ctx, `INSERT INTO ip_addresses (pool_id, ip, daily_cap) VALUES ($1,$2,1)`, poolID, ip); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_ip_assignment (tenant_id, pool_id, dedicated) VALUES ($1,$2,true)`, tenant, poolID); err != nil {
		t.Fatal(err)
	}

	// A loopback listener records the source IP each connection arrives from.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			seen <- h
			c.Close()
		}
	}()

	// The production dialer: resolveMX points every domain at our listener; the
	// IPRouter leases the tenant's source IP, which SourceIPDialer binds.
	ipr := &deliverability.IPRouter{Pool: pool}
	dialer := submit.SourceIPDialer(
		func(ctx context.Context, domain string) ([]submit.MXHost, error) {
			return []submit.MXHost{{Host: dns.Domain{ASCII: "mx.test"}, Addr: ln.Addr().String()}}, nil
		},
		func(ctx context.Context, domain string, mx dns.Domain) (net.IP, error) {
			leased, err := ipr.LeaseSourceIP(ctx, submit.TenantFrom(ctx))
			if err != nil {
				return nil, err
			}
			return leased.IP, nil
		},
	)

	// Two deliveries for the tenant → two distinct leased+bound source IPs.
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		conn, _, err := dialer(submit.WithTenant(ctx, tenant), "recipient.example")
		if err != nil {
			t.Fatalf("delivery %d dial: %v", i, err)
		}
		local, _, _ := net.SplitHostPort(conn.LocalAddr().String())
		conn.Close()
		select {
		case peer := <-seen:
			if peer != local {
				t.Fatalf("delivery %d: peer saw %s but socket bound %s", i, peer, local)
			}
			got[peer] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("delivery %d: listener did not accept", i)
		}
	}

	if !got["127.0.0.2"] || !got["127.0.0.3"] {
		t.Fatalf("expected both egress IPs observed, got %v", got)
	}
	t.Logf("OK: IPRouter leased distinct per-tenant source IPs and SourceIPDialer bound each — peer observed %v", got)
}
