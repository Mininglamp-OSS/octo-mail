package blob

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	// nowFn is overridable in tests; defaults to time.Now.
	nowFn func() time.Time
}

// S3Config configures an S3-compatible blob store.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
}

// NewS3 returns an S3-backed blob store and ensures the bucket exists.
func NewS3(cfg S3Config) (Store, error) {
	s := &s3Store{
		client:    &http.Client{Timeout: 30 * time.Second},
		endpoint:  strings.TrimRight(cfg.Endpoint, "/"),
		region:    cfg.Region,
		bucket:    cfg.Bucket,
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
		nowFn:     time.Now,
	}
	if s.region == "" {
		s.region = "us-east-1"
	}
	if err := s.ensureBucket(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
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
	if err := s.sign(req, emptyHash, nil); err != nil {
		return err
	}
	resp, err := s.client.Do(req)
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
	if err := s.sign(creq, emptyHash, nil); err != nil {
		return err
	}
	cresp, err := s.client.Do(creq)
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
	if ok, _ := s.head(ctx, key); ok {
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
	if err := s.sign(req, payloadHash, nil); err != nil {
		return "", 0, err
	}
	resp, err := s.client.Do(req)
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

func (s *s3Store) head(ctx context.Context, key string) (bool, int64) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.endpoint+"/"+s.bucket+"/"+key, nil)
	if err != nil {
		return false, 0
	}
	if err := s.sign(req, emptyHash, nil); err != nil {
		return false, 0
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}
	return true, resp.ContentLength
}

func (s *s3Store) Open(ctx context.Context, tenantID int64, ref Ref) (Reader, error) {
	if !ref.Valid() {
		return nil, ErrBadRef
	}
	key := s.key(tenantID, ref)
	ok, size := s.head(ctx, key)
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", ref)
	}
	return &s3Reader{s: s, ctx: ctx, key: key, size: size}, nil
}

func (s *s3Store) Delete(ctx context.Context, tenantID int64, ref Ref) error {
	if !ref.Valid() {
		return ErrBadRef
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.endpoint+"/"+s.bucket+"/"+s.key(tenantID, ref), nil)
	if err != nil {
		return err
	}
	if err := s.sign(req, emptyHash, nil); err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("s3 delete: %s", resp.Status)
	}
	return nil
}

// s3Reader streams an object, with ranged ReadAt for IMAP FETCH BODY[]<partial>.
type s3Reader struct {
	s    *s3Store
	ctx  context.Context
	key  string
	size int64
	off  int64
}

func (r *s3Reader) Read(p []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	n, err := r.ReadAt(p, r.off)
	r.off += int64(n)
	return n, err
}

func (r *s3Reader) ReadAt(p []byte, off int64) (int, error) {
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
	if err := r.s.sign(req, emptyHash, nil); err != nil {
		return 0, err
	}
	resp, err := r.s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
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

func (r *s3Reader) Size() int64  { return r.size }
func (r *s3Reader) Close() error { return nil }

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

	// Signed headers: host, x-amz-content-sha256, x-amz-date (+ range if present).
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
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
