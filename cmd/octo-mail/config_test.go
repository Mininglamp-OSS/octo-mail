package main

import "testing"

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
