package webapi

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"
)

// attachment is a base64-encoded file to attach.
type attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType,omitempty"`
	Content     string `json:"content"` // base64
}

// composeInput describes a message to build into RFC 5322 bytes.
type composeInput struct {
	From        string
	To          []string
	Cc          []string
	Subject     string
	Text        string
	HTML        string
	Attachments []attachment
	MessageID   string   // generated if empty
	InReplyTo   string   // parent Message-ID (reply)
	References  []string // reference chain (reply)
}

// compose renders an RFC 5322 message with CRLF line endings and a guaranteed
// trailing CRLF (required by SMTP DATA). It emits text/plain, a
// multipart/alternative for text+HTML, and wraps attachments in multipart/mixed.
func compose(in composeInput, domain string) ([]byte, string, error) {
	msgID := in.MessageID
	if msgID == "" {
		id, err := genMessageID(domain)
		if err != nil {
			return nil, "", err
		}
		msgID = id
	}

	var h bytes.Buffer
	writeHeader(&h, "From", in.From)
	writeHeader(&h, "To", strings.Join(in.To, ", "))
	if len(in.Cc) > 0 {
		writeHeader(&h, "Cc", strings.Join(in.Cc, ", "))
	}
	writeHeader(&h, "Subject", in.Subject)
	writeHeader(&h, "Message-ID", msgID)
	writeHeader(&h, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&h, "MIME-Version", "1.0")
	if in.InReplyTo != "" {
		writeHeader(&h, "In-Reply-To", in.InReplyTo)
	}
	if len(in.References) > 0 {
		writeHeader(&h, "References", strings.Join(in.References, " "))
	}

	body, ctype, err := composeBody(in)
	if err != nil {
		return nil, "", err
	}
	writeHeader(&h, "Content-Type", ctype)
	h.WriteString("\r\n")
	h.Write(body)
	if !bytes.HasSuffix(h.Bytes(), []byte("\r\n")) {
		h.WriteString("\r\n")
	}
	return h.Bytes(), msgID, nil
}

func composeBody(in composeInput) (body []byte, contentType string, err error) {
	hasHTML := in.HTML != ""
	hasAttach := len(in.Attachments) > 0

	if !hasAttach {
		if !hasHTML {
			return []byte(normalizeCRLF(in.Text)), "text/plain; charset=utf-8", nil
		}
		return composeAlternative(in.Text, in.HTML)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if hasHTML {
		altBody, altType, e := composeAlternative(in.Text, in.HTML)
		if e != nil {
			return nil, "", e
		}
		pw, e := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {altType}})
		if e != nil {
			return nil, "", e
		}
		pw.Write(altBody)
	} else {
		pw, e := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
		if e != nil {
			return nil, "", e
		}
		pw.Write([]byte(normalizeCRLF(in.Text)))
	}
	for _, at := range in.Attachments {
		if e := writeAttachment(mw, at); e != nil {
			return nil, "", e
		}
	}
	if e := mw.Close(); e != nil {
		return nil, "", e
	}
	return buf.Bytes(), "multipart/mixed; boundary=" + mw.Boundary(), nil
}

func composeAlternative(text, html string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	tp, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, "", err
	}
	tp.Write([]byte(normalizeCRLF(text)))
	hp, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=utf-8"}})
	if err != nil {
		return nil, "", err
	}
	hp.Write([]byte(normalizeCRLF(html)))
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "multipart/alternative; boundary=" + mw.Boundary(), nil
}

func writeAttachment(mw *multipart.Writer, at attachment) error {
	raw, err := base64.StdEncoding.DecodeString(at.Content)
	if err != nil {
		return errStatus(400, "invalid_attachment", "attachment "+at.Filename+": invalid base64")
	}
	ct := at.ContentType
	if ct == "" {
		if dot := strings.LastIndex(at.Filename, "."); dot >= 0 {
			ct = mime.TypeByExtension(at.Filename[dot:])
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
	}
	h := textproto.MIMEHeader{
		"Content-Type":              {ct},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", at.Filename)},
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		pw.Write([]byte(enc[i:end]))
		pw.Write([]byte("\r\n"))
	}
	return nil
}

// writeHeader writes one folded header line. CR and LF are stripped from the
// value to prevent header injection (e.g. a Subject smuggling extra headers).
func writeHeader(b *bytes.Buffer, name, value string) {
	b.WriteString(name)
	b.WriteString(": ")
	b.WriteString(stripCRLF(value))
	b.WriteString("\r\n")
}

// stripCRLF removes CR and LF so untrusted header values cannot inject headers.
func stripCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// normalizeCRLF converts bare LF and lone CR to CRLF, as required for RFC 5322
// bodies delivered over SMTP DATA (bare LF is rejected with ErrCRLF).
func normalizeCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func genMessageID(domain string) (string, error) {
	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return "", err
	}
	if domain == "" {
		domain = "localhost"
	}
	return fmt.Sprintf("<%s@%s>", base64.RawURLEncoding.EncodeToString(rb), domain), nil
}

// memBlob adapts raw bytes to a store.BlobReader for DeliverMailbox.
func memBlob(b []byte) *memBlobReader { return &memBlobReader{data: b} }

type memBlobReader struct {
	data []byte
	off  int64
}

func (m *memBlobReader) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}

func (m *memBlobReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memBlobReader) Close() error { return nil }
func (m *memBlobReader) Size() int64  { return int64(len(m.data)) }
