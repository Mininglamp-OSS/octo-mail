package addr

import "testing"

func TestDomain(t *testing.T) {
	cases := map[string]string{
		"user@example.com":         "example.com",
		"<user@example.com>":       "example.com",
		"  user@example.com  ":     "example.com",
		"bounces+t.msg@mx.example": "mx.example",
		"noatsign":                 "",
		"@example.com":             "", // missing localpart
		"user@":                    "", // missing domain
		"":                         "",
	}
	for in, want := range cases {
		if got := Domain(in); got != want {
			t.Errorf("Domain(%q) = %q, want %q", in, got, want)
		}
	}
}
