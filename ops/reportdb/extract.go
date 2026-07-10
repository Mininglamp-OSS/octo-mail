package reportdb

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	moxmessage "github.com/mjl-/mox/message"
)

// maxReportBytes bounds a single decompressed report to keep a malicious or
// malformed attachment (e.g. a zip bomb) from exhausting memory during ingest.
const maxReportBytes = 50 << 20 // 50 MiB

// IngestMessage extracts the report attachment from a full RFC822 report message
// and stores it. It walks the MIME tree, and for each leaf part tries, in order:
// gzip, zip, then raw — decompressing as needed — and routes the resulting bytes
// to IngestDMARC (XML) or IngestTLSRPT (JSON) by sniffing the content. It returns
// the kind ingested ("dmarc" or "tlsrpt") or an error if no part yielded a
// parseable report. Callers (the MX ReportHandler) log the error; a report is
// never bounced.
func (s *Store) IngestMessage(ctx context.Context, raw []byte) (string, error) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.MediaType == "" {
		return "", fmt.Errorf("parse report message: %w", err)
	}
	var firstErr error
	for _, body := range reportPayloads(&part) {
		kind, err := s.ingestPayload(ctx, body)
		if err == nil {
			return kind, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", errors.New("no report attachment found in message")
}

// ingestPayload sniffs one decompressed attachment and routes it. DMARC reports
// are XML (root element <feedback>); TLS-RPT reports are JSON. Sniff on the first
// non-space byte: '<' → DMARC XML, '{' → TLS-RPT JSON.
func (s *Store) ingestPayload(ctx context.Context, body []byte) (string, error) {
	// Strip a leading UTF-8 BOM, then leading whitespace, before sniffing.
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), " \t\r\n")
	if len(trimmed) == 0 {
		return "", errors.New("empty report payload")
	}
	switch trimmed[0] {
	case '<':
		if _, err := s.IngestDMARC(ctx, body); err != nil {
			return "", fmt.Errorf("ingest dmarc: %w", err)
		}
		return "dmarc", nil
	case '{':
		if _, err := s.IngestTLSRPT(ctx, body); err != nil {
			return "", fmt.Errorf("ingest tlsrpt: %w", err)
		}
		return "tlsrpt", nil
	default:
		return "", fmt.Errorf("unrecognized report payload (first byte %q)", trimmed[0])
	}
}

// reportPayloads returns the candidate decompressed report bodies from a parsed
// message: for every leaf part, the raw decoded body plus any gzip/zip-extracted
// members. Filename/content-type are only hints; report senders are inconsistent,
// so we try to decode every leaf and let the sniffer decide.
func reportPayloads(p *moxmessage.Part) [][]byte {
	var out [][]byte
	var walk func(*moxmessage.Part)
	walk = func(pt *moxmessage.Part) {
		if len(pt.Parts) > 0 {
			for i := range pt.Parts {
				walk(&pt.Parts[i])
			}
			return
		}
		// Leaf part: read its decoded body (bounded).
		body, err := io.ReadAll(io.LimitReader(pt.Reader(), maxReportBytes))
		if err != nil || len(body) == 0 {
			return
		}
		out = append(out, decompressCandidates(body)...)
	}
	walk(p)
	return out
}

// decompressCandidates returns the bodies to try for one leaf: gzip-decompressed,
// each zip member, or the raw body — whichever apply. A body that is neither gzip
// nor zip is returned as-is (many senders send uncompressed XML/JSON inline).
func decompressCandidates(body []byte) [][]byte {
	// gzip: magic 0x1f 0x8b.
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if dec, err := io.ReadAll(io.LimitReader(zr, maxReportBytes)); err == nil && len(dec) > 0 {
				return [][]byte{dec}
			}
		}
		return nil // declared gzip but undecodable — nothing usable
	}
	// zip: magic "PK\x03\x04".
	if len(body) >= 4 && body[0] == 'P' && body[1] == 'K' && body[2] == 0x03 && body[3] == 0x04 {
		return zipMembers(body)
	}
	// Raw (uncompressed) attachment.
	return [][]byte{body}
}

// zipMembers extracts every file member of a zip archive, each bounded.
func zipMembers(body []byte) [][]byte {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		dec, err := io.ReadAll(io.LimitReader(rc, maxReportBytes))
		rc.Close()
		if err == nil && len(dec) > 0 {
			out = append(out, dec)
		}
	}
	return out
}
