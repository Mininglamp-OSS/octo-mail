package webapi

import (
	"bytes"
	"strings"
	"testing"
)

// TestComposeCRLFAndInjection guards the two compose bugs that single-line body
// tests miss: (1) multi-line bodies must use CRLF (bare LF is rejected by SMTP
// DATA), and (2) header values must not be able to inject extra headers.
func TestComposeCRLFAndInjection(t *testing.T) {
	raw, _, err := compose(composeInput{
		From:    "a@x.test",
		To:      []string{"b@y.test"},
		Subject: "hi\r\nBcc: victim@evil.test", // injection attempt
		Text:    "line1\nline2\nline3",         // bare LF body
	}, "x.test")
	if err != nil {
		t.Fatal(err)
	}

	// (1) No bare LF anywhere: every \n must be preceded by \r.
	for i, b := range raw {
		if b == '\n' && (i == 0 || raw[i-1] != '\r') {
			t.Fatalf("bare LF at offset %d — SMTP DATA would reject this message", i)
		}
	}
	if !bytes.Contains(raw, []byte("line1\r\nline2\r\nline3")) {
		t.Fatalf("body not CRLF-normalized:\n%q", raw)
	}

	// (2) Header injection neutralized: the CRLF in Subject was stripped, so the
	// smuggled Bcc must NOT appear as its own header line.
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	}
	for _, line := range strings.Split(string(head), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("header injection succeeded — smuggled line: %q", line)
		}
	}
	if !bytes.Contains(head, []byte("Subject: hiBcc: victim@evil.test")) {
		t.Fatalf("subject not sanitized as expected:\n%q", head)
	}

	// Trailing CRLF is present (required by SMTP DATA).
	if !bytes.HasSuffix(raw, []byte("\r\n")) {
		t.Fatalf("message does not end with CRLF")
	}
}

// TestComposeAttachmentHeaderInjection guards finding #23-5: a crafted attachment
// Content-Type (or filename) must not inject extra headers into the MIME part.
func TestComposeAttachmentHeaderInjection(t *testing.T) {
	raw, _, err := compose(composeInput{
		From: "a@x.test",
		To:   []string{"b@y.test"},
		Text: "body",
		Attachments: []attachment{{
			Filename:    "ok.txt",
			ContentType: "text/plain\r\nX-Injected: evil", // injection attempt
			Content:     "aGVsbG8=",                       // base64 "hello"
		}},
	}, "x.test")
	if err != nil {
		t.Fatal(err)
	}
	// The smuggled header must not appear as its own line anywhere in the message.
	for _, line := range strings.Split(string(raw), "\r\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "x-injected:") {
			t.Fatalf("attachment Content-Type header injection succeeded: %q", line)
		}
	}
	// The Content-Type is still present, just with the CRLF stripped out.
	if !bytes.Contains(raw, []byte("Content-Type: text/plainX-Injected: evil")) {
		t.Fatalf("attachment content-type not sanitized as expected:\n%q", raw)
	}
	t.Logf("OK: attachment Content-Type CRLF stripped — no header injection")
}
