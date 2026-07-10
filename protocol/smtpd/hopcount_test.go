package smtpd

import "testing"

// TestCountReceivedHeaders covers the hop-count loop guard's counting: only header
// fields that begin a "Received:" line in the header block are counted — not body
// lines, not folded continuations — and both CRLF and bare-LF endings are handled.
func TestCountReceivedHeaders(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want int
	}{
		{"none", "From: a@x\r\nSubject: hi\r\n\r\nbody\r\n", 0},
		{"two", "Received: from a\r\nReceived: from b\r\nSubject: hi\r\n\r\nbody\r\n", 2},
		{"case-insensitive", "received: from a\r\nRECEIVED: from b\r\n\r\nx", 2},
		{"folded continuation not counted", "Received: from a\r\n\tby b\r\n\tfor <c>;\r\nSubject: x\r\n\r\nx", 1},
		{"body Received not counted", "Subject: x\r\n\r\nReceived: from evil\r\nReceived: from evil2\r\n", 0},
		{"bare-LF still counted", "Received: from a\nReceived: from b\nSubject: x\n\nbody\n", 2},
		{"no body separator", "Received: from a\r\nReceived: from b\r\n", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countReceivedHeaders([]byte(c.msg)); got != c.want {
				t.Fatalf("countReceivedHeaders = %d, want %d", got, c.want)
			}
		})
	}
}
