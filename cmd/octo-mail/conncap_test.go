package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServeTCPListenerConnCap proves the H14 per-listener connection cap: with
// maxConns=2, at most two handlers run concurrently; a third connection made
// while both are busy is accepted-then-closed (refused fast) rather than adding
// an unbounded goroutine that could buffer another whole message.
func TestServeTCPListenerConnCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		concurrent atomic.Int32
		peak       atomic.Int32
		handled    atomic.Int32
	)
	release := make(chan struct{})
	handle := func(nc net.Conn) {
		defer nc.Close()
		n := concurrent.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		handled.Add(1)
		<-release // hold the slot until the test releases
		concurrent.Add(-1)
	}

	errc := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go serveTCPListener(ctx, log, "test", "", ln, errc, 2, handle)

	addr := ln.Addr().String()
	// Open two connections that will occupy both slots and block in handle.
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	// Wait until both handlers are actually running (slots occupied).
	deadline := time.Now().Add(5 * time.Second)
	for handled.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d handlers started, want 2", handled.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A third connection while both slots are busy must be refused: the server
	// closes it without running handle, so a read returns EOF promptly.
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial third: %v", err)
	}
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := third.Read(buf); err != io.EOF {
		t.Fatalf("third connection read err = %v, want EOF (refused, not handled)", err)
	}
	third.Close()

	if got := handled.Load(); got != 2 {
		t.Fatalf("handled = %d, want 2 (third must not have run handle)", got)
	}

	// Release the two held handlers and confirm the peak never exceeded the cap.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); close(release) }()
	wg.Wait()
	for _, c := range held {
		c.Close()
	}
	if p := peak.Load(); p > 2 {
		t.Fatalf("peak concurrency = %d, exceeded cap 2", p)
	}
	t.Logf("OK: connection cap held (peak=%d ≤ 2); over-cap connection refused fast", peak.Load())
}

// TestServeHTTPConnCapAndTimeouts proves the H14 coverage for the HTTP front
// doors (JMAP + admin): serveHTTP sets slowloris-defeating timeouts and puts the
// listener behind the maxConns semaphore, so the HTTP doors are bounded like the
// TCP ones. A third concurrent request while two handlers are held is not served
// until a slot frees (limitListener blocks Accept, rather than refusing).
func TestServeHTTPConnCapAndTimeouts(t *testing.T) {
	var (
		inflight atomic.Int32
		peak     atomic.Int32
		served   atomic.Int32
	)
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		served.Add(1)
		<-release
		inflight.Add(-1)
		w.WriteHeader(200)
	})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: h}
	errc := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// serveHTTP binds srv.Addr itself; use a fixed loopback port via a pre-bound
	// listener isn't supported, so bind :0 through serveHTTP and discover the addr.
	// serveHTTP blocks, so run it in a goroutine and poll for the chosen port.
	// (It sets srv.Addr's listener; we read the actual addr from a probe listen.)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv.Addr = addr
	go serveHTTP(log, "test-http", srv, 2, errc)
	defer srv.Close()

	// Timeouts must be set by serveHTTP.
	deadline := time.Now().Add(3 * time.Second)
	for srv.ReadHeaderTimeout == 0 {
		if time.Now().After(deadline) {
			t.Fatal("serveHTTP did not set ReadHeaderTimeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if srv.ReadHeaderTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("timeouts not set: readHeader=%v idle=%v", srv.ReadHeaderTimeout, srv.IdleTimeout)
	}

	get := func() { _, _ = http.Get("http://" + addr + "/") }
	// Wait until the server is accepting.
	for i := 0; i < 200; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Two requests occupy both slots and block in the handler.
	go get()
	go get()
	d2 := time.Now().Add(5 * time.Second)
	for served.Load() < 2 {
		if time.Now().After(d2) {
			t.Fatalf("only %d handlers running, want 2", served.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A third request must NOT get served while the two slots are held.
	go get()
	time.Sleep(300 * time.Millisecond)
	if got := served.Load(); got != 2 {
		t.Fatalf("served=%d while cap=2 slots held — HTTP conn cap not enforced", got)
	}
	// Release; peak must never have exceeded the cap.
	close(release)
	if p := peak.Load(); p > 2 {
		t.Fatalf("peak HTTP concurrency=%d exceeded cap 2", p)
	}
	t.Logf("OK: HTTP listener capped (peak=%d ≤ 2) and timeouts set", peak.Load())
}
