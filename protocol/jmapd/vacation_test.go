package jmapd_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// TestVacationResponse proves JMAP VacationResponse/get+set (RFC 8621 §8): the
// singleton starts disabled; VacationResponse/set enables it with subject/text;
// VacationResponse/get reflects the change. Real HTTP.
func TestVacationResponse(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE accounts, domains, addresses, principals, tenants, vacation_response RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Default: disabled singleton.
	g := call(t, hs.URL, `["VacationResponse/get", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	obj := g["list"].([]any)[0].(map[string]any)
	if obj["id"] != "singleton" {
		t.Fatalf("vacation id = %v, want singleton", obj["id"])
	}
	if obj["isEnabled"] != false {
		t.Fatalf("default isEnabled = %v, want false", obj["isEnabled"])
	}

	// Enable with subject + text.
	setRes := call(t, hs.URL, `["VacationResponse/set", {"accountId":"`+itoa(accID)+`","update":{"singleton":{"isEnabled":true,"subject":"Away","textBody":"I am on vacation until Monday."}}}, "c2"]`)
	if _, ok := setRes["updated"].(map[string]any)["singleton"]; !ok {
		t.Fatalf("VacationResponse/set did not update singleton: %v", setRes)
	}

	// Get reflects the change.
	g2 := call(t, hs.URL, `["VacationResponse/get", {"accountId":"`+itoa(accID)+`"}, "c3"]`)
	obj2 := g2["list"].([]any)[0].(map[string]any)
	if obj2["isEnabled"] != true {
		t.Fatalf("after set, isEnabled = %v, want true", obj2["isEnabled"])
	}
	if obj2["subject"] != "Away" {
		t.Fatalf("after set, subject = %v, want Away", obj2["subject"])
	}
	if obj2["textBody"] != "I am on vacation until Monday." {
		t.Fatalf("after set, textBody = %v", obj2["textBody"])
	}

	// A non-singleton id is rejected.
	bad := call(t, hs.URL, `["VacationResponse/set", {"accountId":"`+itoa(accID)+`","update":{"other":{"isEnabled":false}}}, "c4"]`)
	if _, ok := bad["notUpdated"].(map[string]any)["other"]; !ok {
		t.Fatalf("non-singleton id should be notUpdated: %v", bad)
	}

	t.Logf("OK: VacationResponse singleton get(default disabled)→set(enable+subject+text)→get(reflects); non-singleton rejected")
}
