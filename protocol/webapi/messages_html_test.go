package webapi

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func base64MIMEBody(value string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	var lines []string
	for len(encoded) > 76 {
		lines = append(lines, encoded[:76])
		encoded = encoded[76:]
	}
	return strings.Join(append(lines, encoded), "\r\n")
}

func TestParseBodiesMarksLargeHTMLTruncated(t *testing.T) {
	body := "<head><style>" + strings.Repeat("x", 20*1024) + "</style></head>" +
		"<body><p>Your verification code is <strong>123456</strong>.</p><div>" +
		strings.Repeat("details ", 20*1024) + "</div></body>"
	if len(body) <= maxRenderableHTMLBytes {
		t.Fatalf("test HTML is %d bytes, want over %d", len(body), maxRenderableHTMLBytes)
	}
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		base64MIMEBody(body),
		"",
	}, "\r\n"))

	text, htmlBody, _, truncated := parseBodiesWithTruncation(raw)
	if htmlBody != "" {
		t.Fatalf("HTML body is %d bytes, want omitted", len(htmlBody))
	}
	if text != "" {
		t.Fatalf("text body = %q, want empty without a text/plain alternative", text)
	}
	if !truncated {
		t.Fatal("bodyTruncated = false, want true")
	}
}

func TestParseBodiesKeepsPlainAlternativeForLargeHTML(t *testing.T) {
	body := "<p>REAL HTML BODY " + strings.Repeat("details ", 20*1024) + "</p>"
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"View this email in your browser",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		base64MIMEBody(body),
		"--body--",
		"",
	}, "\r\n"))

	text, htmlBody, _, truncated := parseBodiesWithTruncation(raw)
	if got, want := text, "View this email in your browser"; got != want {
		t.Fatalf("text body = %q, want %q", got, want)
	}
	if htmlBody != "" {
		t.Fatalf("HTML body is %d bytes, want omitted", len(htmlBody))
	}
	if !truncated {
		t.Fatal("bodyTruncated = false, want true")
	}
}

func TestParseBodiesOmitsMultipleHTMLBodies(t *testing.T) {
	for _, mediaType := range []string{"mixed", "alternative"} {
		t.Run(mediaType, func(t *testing.T) {
			raw := []byte(strings.Join([]string{
				"From: sender@example.com",
				"To: receiver@mail.imocto.cn",
				"MIME-Version: 1.0",
				fmt.Sprintf(`Content-Type: multipart/%s; boundary="body"`, mediaType),
				"",
				"--body",
				"Content-Type: text/plain; charset=utf-8",
				"",
				"PLAIN FALLBACK",
				"--body",
				"Content-Type: text/html; charset=utf-8",
				"",
				"<p>FIRST HTML</p>",
				"--body",
				"Content-Type: text/html; charset=utf-8",
				"",
				"<p>SECOND HTML</p>",
				"--body--",
				"",
			}, "\r\n"))

			text, htmlBody, _, truncated := parseBodiesWithTruncation(raw)
			if got, want := text, "PLAIN FALLBACK"; got != want {
				t.Fatalf("text body = %q, want %q", got, want)
			}
			if htmlBody != "" {
				t.Fatalf("HTML body = %q, want omitted", htmlBody)
			}
			if !truncated {
				t.Fatal("bodyTruncated = false, want true")
			}
		})
	}
}

func TestParseBodiesKeepsInlineFilenameBody(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		`Content-Type: text/plain; charset=utf-8; name="body.txt"`,
		`Content-Disposition: inline; filename="body.txt"`,
		"",
		"THE REAL BODY",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "THE REAL BODY" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
	if got, want := previewText(raw), "THE REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewTextSkipsMalformedAttachmentDisposition(t *testing.T) {
	for _, disposition := range []string{
		`attachment; filename="=?gb2312?b?ZXZpbC5odG1s?="`,
		`attachment; filename="report.html"; bad=`,
	} {
		t.Run(disposition, func(t *testing.T) {
			raw := []byte(strings.Join([]string{
				"From: sender@example.com",
				"To: receiver@mail.imocto.cn",
				"MIME-Version: 1.0",
				`Content-Type: multipart/mixed; boundary="body"`,
				"",
				"--body",
				"Content-Type: text/html; charset=utf-8",
				"Content-Disposition: " + disposition,
				"",
				"<p>ATTACHMENT CONTENT</p>",
				"--body",
				"Content-Type: text/plain; charset=utf-8",
				"",
				"REAL BODY",
				"--body--",
				"",
			}, "\r\n"))

			text, html, _ := parseBodies(raw)
			if text != "REAL BODY" || html != "" {
				t.Fatalf("bodies = text %q, html %q", text, html)
			}
			if got, want := previewText(raw), "REAL BODY"; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestParseBodiesKeepsNonAlternativeHTML(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"PLAIN BODY",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>HTML BODY</p>",
		"--body--",
		"",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "PLAIN BODY" || html != "<p>HTML BODY</p>" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
}

func TestPreviewTextIgnoresHTMLAttachment(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Subject: report",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"REAL BODY: meeting at 3pm",
		"--body",
		`Content-Type: text/html; charset=utf-8; name="report.html"`,
		`Content-Disposition: attachment; filename="report.html"`,
		"",
		"<p>ATTACHMENT INNER TEXT</p>",
		"--body--",
		"",
	}, "\r\n"))

	if got, want := previewText(raw), "REAL BODY: meeting at 3pm"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
	text, html, _ := parseBodies(raw)
	if text != "REAL BODY: meeting at 3pm" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
}

func TestParseBodiesSkipsLargeHTMLAttachment(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		`Content-Disposition: attachment; filename="report.html"`,
		"Content-Transfer-Encoding: base64",
		"",
		base64MIMEBody("<p>ATTACHMENT " + strings.Repeat("content ", 20*1024) + "</p>"),
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"THE REAL BODY TEXT",
		"--body--",
		"",
	}, "\r\n"))

	text, htmlBody, _, truncated := parseBodiesWithTruncation(raw)
	if got, want := text, "THE REAL BODY TEXT"; got != want {
		t.Fatalf("text body = %q, want %q", got, want)
	}
	if htmlBody != "" {
		t.Fatalf("HTML body = %q, want empty", htmlBody)
	}
	if truncated {
		t.Fatal("bodyTruncated = true for an attachment")
	}
}

func TestParseBodiesKeepsTopLevelDispositionBody(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Disposition: attachment",
		"",
		"REAL BODY",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "REAL BODY" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
	if got, want := previewText(raw), "REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}
