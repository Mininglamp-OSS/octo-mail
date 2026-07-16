package acme

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookSolverSignsAndSends(t *testing.T) {
	secret := []byte("s3cr3t")
	var gotBody []byte
	var gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Octo-Signature")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := NewWebhookSolver(srv.URL, secret, srv.Client())

	if err := s.Present(context.Background(), "_acme-challenge.mail.example.com", "tokenval"); err != nil {
		t.Fatal(err)
	}

	// Body is the expected JSON.
	var req dnsWebhookRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, gotBody)
	}
	if req.Op != "present" || req.FQDN != "_acme-challenge.mail.example.com" || req.Value != "tokenval" {
		t.Fatalf("unexpected body: %+v", req)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type: %q", gotCT)
	}

	// Signature matches HMAC-SHA256(secret, body).
	mac := hmac.New(sha256.New, secret)
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature: want %q, got %q", want, gotSig)
	}

	// Body carries a timestamp (anti-replay); it is part of the signed bytes.
	if req.TS == 0 {
		t.Fatalf("expected non-zero ts in signed body: %+v", req)
	}
}

func TestWebhookSolverErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewWebhookSolver(srv.URL, nil, srv.Client())
	if err := s.CleanUp(context.Background(), "_acme-challenge.x.example.com", "v"); err == nil {
		t.Fatal("want error on 500, got nil")
	}
}
