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

const (
	// maxReportBytes bounds a SINGLE decompressed stream (one gzip body or one zip
	// member) so a malformed/malicious attachment can't expand unboundedly.
	maxReportBytes = 50 << 20 // 50 MiB
	// maxTotalReportBytes bounds the CUMULATIVE decompressed bytes across every
	// member/leaf of one message. Without this, a small zip with many members that
	// each expand to maxReportBytes (a decompression bomb) would still buffer
	// gigabytes. The report ingest path is reachable by unauthenticated remote
	// senders, so this ceiling is a DoS control, not just a sanity limit.
	maxTotalReportBytes = 100 << 20 // 100 MiB
	// maxReportMembers caps how many candidate streams one message may yield, so a
	// zip with a huge member count can't drive unbounded work even under the byte
	// budget.
	maxReportMembers = 128
)

// errReportTooLarge signals a decompressed payload exceeded a size/count budget —
// treated as a (likely hostile) oversized report, not silently truncated.
var errReportTooLarge = errors.New("reportdb: report payload exceeds size budget")

// reportBudget tracks the decompression allowance remaining for one message,
// shared across all its members/leaves so the aggregate is bounded.
type reportBudget struct {
	bytesLeft   int64
	membersLeft int
}

// IngestMessage extracts the report attachment from a full RFC822 report message
// and stores it. It walks the MIME tree and, for each leaf, tries gzip, zip, then
// raw — decompressing as needed under a shared per-message budget — and routes the
// resulting bytes to IngestDMARC (XML) or IngestTLSRPT (JSON) by sniffing the
// content. Candidates are processed ONE AT A TIME (never all accumulated), so peak
// memory is one decompressed stream, not the whole archive. owned, if non-nil,
// must return true for the report's policy-published domain or the report is
// rejected (see IngestDMARC/IngestTLSRPT) — so an unauthenticated peer cannot
// inject or suppress reports for domains this node does not serve.
//
// Returns the kind ingested ("dmarc"/"tlsrpt") or an error. Callers (the MX
// ReportHandler) log the error; a report is never bounced.
func (s *Store) IngestMessage(ctx context.Context, raw []byte, owned OwnedDomain) (string, error) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.MediaType == "" {
		return "", fmt.Errorf("parse report message: %w", err)
	}
	budget := &reportBudget{bytesLeft: maxTotalReportBytes, membersLeft: maxReportMembers}
	var firstErr error
	kind, err := s.walkPayloads(ctx, &part, budget, owned, &firstErr)
	if err != nil {
		return "", err // budget exceeded — surface distinctly from a parse miss
	}
	if kind != "" {
		return kind, nil
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", errors.New("no report attachment found in message")
}

// walkPayloads descends the MIME tree, decoding each leaf's candidate payloads
// under the shared budget and attempting to ingest each. It returns the kind on
// the first successful ingest, or a non-nil error only for a budget violation
// (which aborts the whole message). Per-payload ingest failures are recorded in
// firstErr and iteration continues.
func (s *Store) walkPayloads(ctx context.Context, pt *moxmessage.Part, b *reportBudget, owned OwnedDomain, firstErr *error) (string, error) {
	if len(pt.Parts) > 0 {
		for i := range pt.Parts {
			kind, err := s.walkPayloads(ctx, &pt.Parts[i], b, owned, firstErr)
			if err != nil || kind != "" {
				return kind, err
			}
		}
		return "", nil
	}
	// Leaf part: read its decoded body under the budget, then expand candidates.
	body, err := readCapped(pt.Reader(), b)
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", nil
	}
	return s.ingestCandidates(ctx, body, b, owned, firstErr)
}

// ingestCandidates decompresses one leaf body (gzip / each zip member / raw) under
// the shared budget and attempts to ingest each in turn, stopping at the first
// success. Only one decompressed stream is held at a time.
func (s *Store) ingestCandidates(ctx context.Context, body []byte, b *reportBudget, owned OwnedDomain, firstErr *error) (string, error) {
	try := func(payload []byte) (string, bool) {
		kind, err := s.ingestPayload(ctx, payload, owned)
		if err == nil {
			return kind, true
		}
		if *firstErr == nil {
			*firstErr = err
		}
		return "", false
	}

	switch {
	case len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b: // gzip magic
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return "", nil // declared gzip but undecodable — nothing usable
		}
		dec, err := readCapped(zr, b)
		if err != nil {
			return "", err
		}
		if len(dec) > 0 {
			if kind, ok := try(dec); ok {
				return kind, nil
			}
		}
		return "", nil
	case len(body) >= 4 && body[0] == 'P' && body[1] == 'K' && body[2] == 0x03 && body[3] == 0x04: // zip magic
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return "", nil
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			dec, err := readCapped(rc, b)
			rc.Close()
			if err != nil {
				return "", err // budget exceeded → abort the whole message
			}
			if len(dec) == 0 {
				continue
			}
			if kind, ok := try(dec); ok {
				return kind, nil
			}
		}
		return "", nil
	default: // raw (uncompressed) attachment
		if kind, ok := try(body); ok {
			return kind, nil
		}
		return "", nil
	}
}

// readCapped reads one stream, charging it against the shared budget. It caps the
// single stream at maxReportBytes and the cumulative message total at
// maxTotalReportBytes, and rejects (rather than silently truncates) an overflow by
// reading one byte past the limit — mirroring the MaxSize+1 overflow check on the
// SMTP DATA path. It also decrements the member allowance.
func readCapped(r io.Reader, b *reportBudget) ([]byte, error) {
	if b.membersLeft <= 0 {
		return nil, errReportTooLarge
	}
	b.membersLeft--
	limit := int64(maxReportBytes)
	if b.bytesLeft < limit {
		limit = b.bytesLeft
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errReportTooLarge
	}
	b.bytesLeft -= int64(len(data))
	return data, nil
}

// ingestPayload sniffs one decompressed attachment and routes it. DMARC reports
// are XML (root element <feedback>); TLS-RPT reports are JSON. Sniff on the first
// non-space byte: '<' → DMARC XML, '{' → TLS-RPT JSON.
func (s *Store) ingestPayload(ctx context.Context, body []byte, owned OwnedDomain) (string, error) {
	// Strip a leading UTF-8 BOM, then leading whitespace, before sniffing.
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), " \t\r\n")
	if len(trimmed) == 0 {
		return "", errors.New("empty report payload")
	}
	switch trimmed[0] {
	case '<':
		if _, err := s.ingestDMARC(ctx, body, owned); err != nil {
			return "", fmt.Errorf("ingest dmarc: %w", err)
		}
		return "dmarc", nil
	case '{':
		if _, err := s.ingestTLSRPT(ctx, body, owned); err != nil {
			return "", fmt.Errorf("ingest tlsrpt: %w", err)
		}
		return "tlsrpt", nil
	default:
		return "", fmt.Errorf("unrecognized report payload (first byte %q)", trimmed[0])
	}
}
