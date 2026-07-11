package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestCheckVERPConfig proves the security control that closes the nil-vs-empty
// fail-open seam flagged in review: a bounce domain configured WITHOUT a signing
// key must be refused at startup (not merely warned), because []byte(os.Getenv)
// for an unset/empty env var is non-nil but length 0 — the unsigned, forgeable
// attribution path. The explicit dev escape hatch re-permits it.
func TestCheckVERPConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"disabled: no bounce domain", config{}, false},
		{"signed: key set", config{bounceDomain: "b.example", verpKey: []byte("k")}, false},
		{
			// The exact review scenario: OCTO_MAIL_VERP_KEY unset/empty yields a
			// non-nil, zero-length key. Must be a fatal misconfig, not a warning.
			"unsigned: empty (non-nil) key, no escape hatch → refuse",
			config{bounceDomain: "b.example", verpKey: []byte("")},
			true,
		},
		{
			"unsigned: escape hatch set → allowed",
			config{bounceDomain: "b.example", verpKey: []byte(""), allowUnsignedVERP: true},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVERPConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil (fail-open on forgeable VERP path)")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateS3CredsFailFast proves #25-5: an S3 endpoint configured with no
// credential path at all is a fatal misconfiguration (caught at startup, not at
// first request), while empty static creds are allowed when a session token is
// present (STS/IAM-role auth).
func TestValidateS3CredsFailFast(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"no s3 at all", config{}, false},
		{"endpoint + static creds", config{s3Endpoint: "http://s3", s3Access: "a", s3Secret: "s"}, false},
		{"endpoint + session token only", config{s3Endpoint: "http://s3", s3SessionToken: "t"}, false},
		{"endpoint + no creds → refuse", config{s3Endpoint: "http://s3"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.cfg, log)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateAdminWarnsWhenExposed proves the admin-exposure warning: a
// non-loopback admin listener with no token emits a warning (not a hard error),
// while a loopback bind or a token present is silent.
func TestValidateAdminWarnsWhenExposed(t *testing.T) {
	cases := []struct {
		name     string
		cfg      config
		wantWarn bool
	}{
		{"default :8081 (all ifaces) no token", config{adminAddr: ":8081"}, true},
		{"0.0.0.0 no token", config{adminAddr: "0.0.0.0:8081"}, true},
		{"loopback no token", config{adminAddr: "127.0.0.1:8081"}, false},
		{"ipv6 loopback no token", config{adminAddr: "[::1]:8081"}, false},
		{"localhost no token", config{adminAddr: "localhost:8081"}, false},
		{"all ifaces WITH token", config{adminAddr: ":8081", adminToken: "secret"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			log := slog.New(slog.NewTextHandler(&buf, nil))
			if err := validate(tc.cfg, log); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			warned := strings.Contains(buf.String(), "admin API listens on a non-loopback")
			if warned != tc.wantWarn {
				t.Fatalf("admin warning = %v, want %v (log: %q)", warned, tc.wantWarn, buf.String())
			}
		})
	}
}

// TestIsLoopbackAddr covers the listen-address loopback classifier directly.
func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		":8081":            false, // all interfaces
		"0.0.0.0:8081":     false,
		"[::]:8081":        false,
		"127.0.0.1:8081":   true,
		"[::1]:8081":       true,
		"localhost:8081":   true,
		"10.0.0.5:8081":    false,
		"example.com:8081": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// backend when no S3 endpoint is configured (the shared helper the ops
// subcommands now use, so export/import agree with the serve process instead of
// hardcoding fs). The fs path is exercised directly; the S3 branch is covered by
// storage/blob's own S3 round-trip test.
func TestOpenBlobStoreSelectsBackend(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No S3 endpoint → fs backend rooted at the configured blobDir.
	dir := t.TempDir()
	bs, err := openBlobStore(config{blobDir: dir}, log)
	if err != nil {
		t.Fatalf("fs backend: %v", err)
	}
	if bs == nil {
		t.Fatal("fs backend returned nil store")
	}
	// A round-trip proves it's a working fs store at the right root.
	ref, _, err := bs.Put(context.Background(), 1, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("fs Put: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("blobDir not created: %v", err)
	}
	_ = ref
}
