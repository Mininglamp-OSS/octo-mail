package blob

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// s3Store is an S3-compatible blob backend (tested against MinIO). It speaks the
// S3 REST API directly with AWS Signature V4 — no SDK dependency — keeping the
// kernel free of a heavy vendored client. Bodies are content-addressed exactly
// like the fs backend: key = <tenant>/<ab>/<cd>/<sha256>, so identical messages
// dedup within a tenant (a PUT of an existing key is idempotent).
//
// Ranged reads (IMAP FETCH BODY[]<partial>) map to HTTP Range GETs, so a partial
// fetch never streams the whole object.
type s3Store struct {
	client    *http.Client
	endpoint  string // e.g. "http://localhost:29000" (no trailing slash)
	region    string
	bucket    string
	accessKey string
	secretKey string
	// sessionToken, when set, is the STS/IAM-role temporary-credential token; it is
	// sent as X-Amz-Security-Token and included in the SigV4 signed headers. Empty
	// for static long-lived credentials.
	sessionToken string
	// maxAttempts bounds per-request retries on transient failures (5xx / SlowDown /
	// network errors). attemptTimeout bounds each individual attempt (so a stuck
	// attempt is abandoned and retried, while a long-but-progressing streaming body
	// is not capped by a whole-request deadline).
	maxAttempts    int
	attemptTimeout time.Duration
	// nowFn is overridable in tests; defaults to time.Now.
	nowFn func() time.Time
}

// S3Config configures an S3-compatible blob store.
type S3Config struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string // optional STS/IAM-role temporary-credential token
}

// NewS3 returns an S3-backed blob store and ensures the bucket exists.
func NewS3(cfg S3Config) (Store, error) {
	s := &s3Store{
		// No whole-request Client.Timeout: a large streaming GET/PUT body can take
		// longer than any fixed cap. Bound the risky phases (connect, TLS, response
		// headers, idle keep-alive) at the transport, and apply a per-ATTEMPT deadline
		// in retryDo — so a stalled attempt is retried without aborting a slow but
		// steadily-progressing transfer.
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConnsPerHost:   32,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		endpoint:       strings.TrimRight(cfg.Endpoint, "/"),
		region:         cfg.Region,
		bucket:         cfg.Bucket,
		accessKey:      cfg.AccessKey,
		secretKey:      cfg.SecretKey,
		sessionToken:   cfg.SessionToken,
		maxAttempts:    4,
		attemptTimeout: 5 * time.Minute,
		nowFn:          time.Now,
	}
	if s.region == "" {
		s.region = "us-east-1"
	}
	if err := s.ensureBucket(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// retryDo signs and sends req, retrying on transient failures (network error,
// 5xx, or S3 503 SlowDown) with capped exponential backoff + jitter, up to
// maxAttempts. Each attempt gets its own timeout (attemptTimeout) derived from the
// caller's ctx. payloadHash is the SigV4 X-Amz-Content-Sha256 for the (unchanging)
// body; the request must be replayable (idempotent method, or GetBody set for a
// body) since a retry re-sends it. The returned response's body is the caller's to
// close.
func (s *s3Store) retryDo(req *http.Request, payloadHash string) (*http.Response, error) {
	parentCtx := req.Context()
	var lastErr error
	for attempt := 0; attempt < s.maxAttempts; attempt++ {
		if attempt > 0 {
			// Backoff: base 200ms, doubling, capped at 5s, ±20% jitter.
			d := 200 * time.Millisecond << uint(attempt-1)
			if d > 5*time.Second {
				d = 5 * time.Second
			}
			d = time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
			select {
			case <-parentCtx.Done():
				return nil, parentCtx.Err()
			case <-time.After(d):
			}
		}
		// Fresh per-attempt request: reset the body from GetBody (net/http consumes
		// it on send) and re-sign under a per-attempt deadline.
		attemptCtx, cancel := context.WithTimeout(parentCtx, s.attemptTimeout)
		r := req.Clone(attemptCtx)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				cancel()
				return nil, err
			}
			r.Body = body
		}
		if err := s.sign(r, payloadHash, nil); err != nil {
			cancel()
			return nil, err
		}
		resp, err := s.client.Do(r)
		if err != nil {
			cancel()
			lastErr = err
			if parentCtx.Err() != nil {
				return nil, parentCtx.Err()
			}
			continue // network error: retry
		}
		if s.retryableStatus(resp.StatusCode) && attempt < s.maxAttempts-1 {
			// Drain+close so the connection can be reused, then retry.
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("s3: retryable status %s", resp.Status)
			continue
		}
		// Success or a non-retryable/last response. The per-attempt cancel must
		// outlive the body read, so tie it to the body's Close.
		resp.Body = &cancelReadCloser{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("s3: request failed")
	}
	return nil, lastErr
}

func (s *s3Store) retryableStatus(code int) bool {
	return code == http.StatusServiceUnavailable || // 503 (incl. SlowDown)
		code == http.StatusInternalServerError || // 500
		code == http.StatusBadGateway || // 502
		code == http.StatusGatewayTimeout // 504
}

// cancelReadCloser ties a per-attempt context cancel to the response body's
// Close, so the attempt deadline covers the full body read without a goroutine
// leak (the cancel fires when the caller closes the body).
type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func (s *s3Store) key(tenantID int64, ref Ref) string {
	h := string(ref)
	ab, cd := "00", "00"
	if len(h) >= 4 {
		ab, cd = h[0:2], h[2:4]
	}
	return itoa(tenantID) + "/" + ab + "/" + cd + "/" + h
}

func (s *s3Store) ensureBucket(ctx context.Context) error {
	// HEAD bucket; create on 404.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.endpoint+"/"+s.bucket, nil)
	if err != nil {
		return err
	}
	resp, err := s.retryDo(req, emptyHash)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	// Create the bucket (PUT).
	creq, err := http.NewRequestWithContext(ctx, http.MethodPut, s.endpoint+"/"+s.bucket, nil)
	if err != nil {
		return err
	}
	cresp, err := s.retryDo(creq, emptyHash)
	if err != nil {
		return err
	}
	defer cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK && cresp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(cresp.Body)
		return fmt.Errorf("s3 create bucket: %s: %s", cresp.Status, string(b))
	}
	return nil
}

func (s *s3Store) Put(ctx context.Context, tenantID int64, r io.Reader) (Ref, int64, error) {
	// Content-addressing needs the SHA-256 of the whole body (it is both the object
	// key and the SigV4 payload hash), so every byte must pass through the hasher.
	// To avoid holding the whole (up to MaxSize) message in RAM per concurrent
	// upload — a multiplier on the connection-cap OOM budget — spool to a temp file
	// while hashing, then stream the PUT body from that file.
	tmp, err := os.CreateTemp("", "octo-blob-*")
	if err != nil {
		return "", 0, err
	}
	// Close before Remove: on some platforms an open file can't be removed.
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return "", 0, err
	}
	sum := h.Sum(nil)
	ref := Ref(hex.EncodeToString(sum))
	key := s.key(tenantID, ref)

	// Idempotent: skip if the object already exists.
	if ok, _, _ := s.head(ctx, key); ok {
		return ref, size, nil
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	url := s.endpoint + "/" + s.bucket + "/" + key
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, tmp)
	if err != nil {
		return "", 0, err
	}
	req.ContentLength = size
	// Restore transport-level retry safety: with an *os.File body, net/http can't
	// auto-populate GetBody (it does for bytes.Reader), so a PUT racing a
	// server-closed idle keep-alive wouldn't be replayed. Reopen the temp file on
	// demand; the object is content-addressed/idempotent, so a retry is safe.
	req.GetBody = func() (io.ReadCloser, error) {
		f, err := os.Open(tmp.Name())
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	payloadHash := hex.EncodeToString(sum)
	resp, err := s.retryDo(req, payloadHash)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("s3 put: %s: %s", resp.Status, string(b))
	}
	return ref, size, nil
}

// head probes a key. It returns (found, size, err): err is non-nil only for a
// transient failure (network, signing, non-404 status) — the caller should
// retry. A definitive 404 is (false, 0, nil): the object is permanently absent.
func (s *s3Store) head(ctx context.Context, key string) (bool, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.endpoint+"/"+s.bucket+"/"+key, nil)
	if err != nil {
		return false, 0, err
	}
	resp, err := s.retryDo(req, emptyHash)
	if err != nil {
		return false, 0, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, 0, nil // definitively absent
	}
	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("s3 head: %s", resp.Status) // transient/unexpected
	}
	return true, resp.ContentLength, nil
}

func (s *s3Store) Open(ctx context.Context, tenantID int64, ref Ref) (Reader, error) {
	if !ref.Valid() {
		return nil, ErrBadRef
	}
	key := s.key(tenantID, ref)
	// No eager HEAD: size and existence are discovered from the first GET
	// (Content-Range/Content-Length). ErrNotFound surfaces on that first read.
	return &s3Reader{s: s, ctx: ctx, key: key, size: -1}, nil
}

func (s *s3Store) Delete(ctx context.Context, tenantID int64, ref Ref) error {
	if !ref.Valid() {
		return ErrBadRef
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.endpoint+"/"+s.bucket+"/"+s.key(tenantID, ref), nil)
	if err != nil {
		return err
	}
	resp, err := s.retryDo(req, emptyHash)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("s3 delete: %s", resp.Status)
	}
	return nil
}

// s3Reader streams an object. Forward sequential Read holds ONE open GET body and
// consumes it in order — an io.ReadAll (the dominant access pattern: FTS,
// threading, delivery, IMAP fetch) becomes a single GET instead of one signed
// ranged GET per buffer chunk. Out-of-order ReadAt (rare: IMAP FETCH
// BODY[]<partial>) issues an independent ranged GET without disturbing the held
// sequential stream. size is -1 until learned from the first GET or a lazy HEAD.
type s3Reader struct {
	s    *s3Store
	ctx  context.Context
	key  string
	size int64
	off  int64

	body   io.ReadCloser // held streaming GET body for sequential Read; nil until opened
	bodyAt int64         // stream position the held body will next yield
}

// ensureSize populates size without reading the body, for a Size() call that
// precedes any Read (e.g. deliverer measuring the message). Uses a HEAD.
func (r *s3Reader) ensureSize() error {
	if r.size >= 0 {
		return nil
	}
	ok, size, err := r.s.head(r.ctx, r.key)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	r.size = size
	return nil
}

// openStream starts (or restarts) the held GET body at offset off.
func (r *s3Reader) openStream(off int64) error {
	if r.body != nil {
		r.body.Close()
		r.body = nil
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.s.endpoint+"/"+r.s.bucket+"/"+r.key, nil)
	if err != nil {
		return err
	}
	if off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := r.s.retryDo(req, emptyHash)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return fmt.Errorf("s3 get: %s: %s", resp.Status, string(b))
	}
	// Learn the total size from the response if not yet known: Content-Range
	// "bytes X-Y/TOTAL" for a ranged GET, else Content-Length for a full GET.
	if r.size < 0 {
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if i := strings.LastIndexByte(cr, '/'); i >= 0 {
				if total, perr := parseInt64(cr[i+1:]); perr == nil {
					r.size = total
				}
			}
		}
		if r.size < 0 && resp.ContentLength >= 0 {
			r.size = off + resp.ContentLength
		}
	}
	r.body = resp.Body
	r.bodyAt = off
	return nil
}

func (r *s3Reader) Read(p []byte) (int, error) {
	if r.size >= 0 && r.off >= r.size {
		return 0, io.EOF
	}
	// (Re)open the stream if not open or if a prior ReadAt/seek moved off away from
	// where the held body is positioned.
	if r.body == nil || r.bodyAt != r.off {
		if err := r.openStream(r.off); err != nil {
			return 0, err
		}
	}
	n, err := r.body.Read(p)
	r.off += int64(n)
	r.bodyAt += int64(n)
	if err == io.EOF {
		// Body exhausted; drop it so a subsequent Read reopens if needed.
		r.body.Close()
		r.body = nil
		if r.size < 0 || r.off >= r.size {
			return n, io.EOF
		}
		// Short body without hitting size (rare): let the caller call again.
		if n > 0 {
			return n, nil
		}
		return n, io.EOF
	}
	return n, err
}

func (r *s3Reader) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ensureSize(); err != nil {
		return 0, err
	}
	if off >= r.size {
		return 0, io.EOF
	}
	end := off + int64(len(p)) - 1
	if end >= r.size {
		end = r.size - 1
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.s.endpoint+"/"+r.s.bucket+"/"+r.key, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, end))
	resp, err := r.s.retryDo(req, emptyHash)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("s3 get range: %s: %s", resp.Status, string(b))
	}
	n, err := io.ReadFull(resp.Body, p[:end-off+1])
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	if err == nil && off+int64(n) >= r.size {
		err = io.EOF
	}
	return n, err
}

func (r *s3Reader) Size() int64 {
	// BlobReader.Size() may be called before any Read; learn it lazily via HEAD.
	if r.size < 0 {
		_ = r.ensureSize()
	}
	return r.size
}

func (r *s3Reader) Close() error {
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}

// --- AWS Signature V4 (minimal, header-based) ---

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// sign adds the SigV4 Authorization header to req. payloadHash is the hex
// sha256 of the body (emptyHash for no body); data is unused beyond length but
// kept for clarity.
func (s *s3Store) sign(req *http.Request, payloadHash string, _ []byte) error {
	now := s.nowFn().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	// Canonical request.
	canonicalURI := s3EscapePath(req.URL.Path)
	canonicalQuery := canonicalizeQuery(req.URL.RawQuery)

	// Signed headers: host, x-amz-content-sha256, x-amz-date (+ range if present,
	// + security-token for STS/IAM temp creds). x-amz-security-token MUST be both
	// set AND signed, or the signature is rejected.
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
		headers["x-amz-security-token"] = s.sessionToken
	}
	if rng := req.Header.Get("Range"); rng != "" {
		headers["range"] = rng
	}
	var names []string
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k)
		ch.WriteString(":")
		ch.WriteString(strings.TrimSpace(headers[k]))
		ch.WriteString("\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		ch.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// String to sign.
	scope := dateStamp + "/" + s.region + "/s3/aws4_request"
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	// Signing key.
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, s.region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// parseInt64 parses a base-10 int64 (used for the total from a Content-Range).
func parseInt64(s string) (int64, error) {
	var v int64
	if s == "" {
		return 0, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		v = v*10 + int64(c-'0')
	}
	return v, nil
}

// s3EscapePath percent-encodes a path per SigV4 (each segment, keeping '/').
func s3EscapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = s3EscapeSegment(s)
	}
	return strings.Join(segs, "/")
}

func s3EscapeSegment(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b.WriteByte(r)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{r})))
		}
	}
	return b.String()
}

func canonicalizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	sort.Strings(parts)
	for i, p := range parts {
		if !strings.Contains(p, "=") {
			parts[i] = p + "="
		}
	}
	return strings.Join(parts, "&")
}
