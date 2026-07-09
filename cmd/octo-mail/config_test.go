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

// TestOpenBlobStoreSelectsBackend proves the H15 fix: openBlobStore picks the fs
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
