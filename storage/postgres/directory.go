package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/security/auth"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// Compile-time assertions that the Postgres impls satisfy the kernel interfaces.
var (
	_ store.Account           = (*account)(nil)
	_ store.Tx                = (*pgTx)(nil)
	_ directory.Directory     = (*Directory)(nil)
	_ directory.TenantScope   = (*tenantScope)(nil)
	_ directory.InboundTarget = (*inboundTarget)(nil)
)

// Directory is the Postgres-backed identity object graph. It is the only way to
// obtain account handles; tenant isolation is structural (you navigate from a
// TenantScope, never by global id).
type Directory struct {
	s *Store
}

// NewDirectory returns the directory backed by the store.
func (s *Store) NewDirectory() *Directory { return &Directory{s: s} }

// OpenAccountForOps returns a read/write account handle for operator tasks
// (backup/restore, maintenance) by tenant name + account name. It is NOT part of
// the tenant-isolation capability graph — it is a privileged, out-of-band
// accessor for the octo-mail CLI running with DB credentials, never exposed to a
// network principal.
func (s *Store) OpenAccountForOps(ctx context.Context, tenant, account string) (store.Account, error) {
	var tenantID, accID int64
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE name=$1`, tenant).Scan(&tenantID); err != nil {
		return nil, fmt.Errorf("tenant %q: %w", tenant, err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM accounts WHERE tenant_id=$1 AND name=$2`, tenantID, account).Scan(&accID); err != nil {
		return nil, fmt.Errorf("account %q: %w", account, err)
	}
	return s.openAccount(accID, tenantID, account), nil
}

// openAccount constructs an account handle. Package-internal: callers reach it
// only via a TenantScope or InboundTarget, never directly by id.
func (s *Store) openAccount(id, tenantID int64, name string) *account {
	return &account{s: s, id: id, tenantID: tenantID, name: name}
}

func (d *Directory) AuthenticatePrincipal(ctx context.Context, login string, cred directory.Credential) (directory.TenantScope, directory.Principal, error) {
	fail := fmt.Errorf("authentication failed")
	var p directory.Principal
	var credJSON []byte
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, login, cred FROM principals WHERE login=$1`, login).
		Scan(&p.ID, &p.TenantID, &p.Login, &credJSON)
	if err == pgx.ErrNoRows {
		// Spend the same argon2 cost on a missing login as on an existing one, so
		// response timing can't be used to enumerate valid logins. Only for the
		// password credential (the nil/resolve-only path is internal, not network).
		if c, ok := cred.(directory.PasswordCredential); ok {
			auth.VerifyDummy(string(c))
		}
		return nil, directory.Principal{}, fail
	}
	if err != nil {
		return nil, directory.Principal{}, err
	}

	// Verify the credential. A nil credential means "resolve only" — permitted
	// solely for trusted internal callers, never for a network principal. Network
	// entry points (imapd/smtpd/jmapd) always pass a directory.PasswordCredential.
	switch c := cred.(type) {
	case directory.PasswordCredential:
		if !auth.Verify(credJSON, string(c)) {
			return nil, directory.Principal{}, fail
		}
	case nil:
		// resolve-only (internal). Left for trusted callers; do not expose.
	default:
		return nil, directory.Principal{}, fail
	}

	ts, err := d.tenantScope(ctx, p.TenantID)
	if err != nil {
		return nil, directory.Principal{}, err
	}
	return ts, p, nil
}

// LookupSCRAM returns the stored SCRAM-SHA-256 verifier for a login, so the
// protocol layer can drive the SASL exchange. Errors (including no such
// principal or no SCRAM verifier stored) are returned uniformly to avoid
// leaking which logins exist.
func (d *Directory) LookupSCRAM(ctx context.Context, login string) (directory.SCRAMVerifier, error) {
	fail := fmt.Errorf("authentication failed")
	var credJSON []byte
	err := d.s.Pool.QueryRow(ctx, `SELECT cred FROM principals WHERE login=$1`, login).Scan(&credJSON)
	if err == pgx.ErrNoRows {
		return directory.SCRAMVerifier{}, fail
	}
	if err != nil {
		return directory.SCRAMVerifier{}, err
	}
	salt, saltedPwd, iters, ok := auth.SCRAMVerifier(credJSON)
	if !ok {
		return directory.SCRAMVerifier{}, fail
	}
	return directory.SCRAMVerifier{Salt: salt, SaltedPassword: saltedPwd, Iterations: iters}, nil
}

// ScopeForLogin returns the tenant scope for a login WITHOUT any credential
// check. It is only called by the protocol layer after a SCRAM proof has already
// verified the client; it must never be exposed as an authentication bypass.
func (d *Directory) ScopeForLogin(ctx context.Context, login string) (directory.TenantScope, directory.Principal, error) {
	var p directory.Principal
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, login FROM principals WHERE login=$1`, login).
		Scan(&p.ID, &p.TenantID, &p.Login)
	if err == pgx.ErrNoRows {
		return nil, directory.Principal{}, fmt.Errorf("no such principal")
	}
	if err != nil {
		return nil, directory.Principal{}, err
	}
	ts, err := d.tenantScope(ctx, p.TenantID)
	if err != nil {
		return nil, directory.Principal{}, err
	}
	return ts, p, nil
}

// SetPassword sets/updates a principal's password (argon2id). Used by admin/
// provisioning and tests.
func (d *Directory) SetPassword(ctx context.Context, login, password string) error {
	c, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	credJSON, err := c.Marshal()
	if err != nil {
		return err
	}
	ct, err := d.s.Pool.Exec(ctx, `UPDATE principals SET cred=$2 WHERE login=$1`, login, credJSON)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("no such principal %q", login)
	}
	return nil
}

// IssueAPIKey mints an account-scoped API key for a login and stores a hash of
// its secret half. The full token (omk_<prefix>_<secret>) is returned once and
// never recoverable afterward. login must be an email address that maps to an
// account (the address the key will act as).
func (d *Directory) IssueAPIKey(ctx context.Context, login, name string) (string, error) {
	if name == "" {
		name = "api key"
	}
	var principalID, tenantID int64
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id FROM principals WHERE login=$1`, login).Scan(&principalID, &tenantID)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("no such principal %q", login)
	}
	if err != nil {
		return "", err
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return "", fmt.Errorf("login must be an email address: %w", err)
	}
	var accountID int64
	err = d.s.Pool.QueryRow(ctx,
		`SELECT a.account_id
		 FROM addresses a
		 JOIN domains dom ON dom.id = a.domain_id
		 WHERE a.tenant_id=$1 AND dom.domain=$2 AND a.localpart=$3`,
		tenantID, addr.Domain.Name(), string(addr.Localpart)).Scan(&accountID)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("no account for address %q", login)
	}
	if err != nil {
		return "", err
	}

	prefix, secret, err := newAPIKeyToken()
	if err != nil {
		return "", err
	}
	cred, err := auth.HashAPIKey(secret)
	if err != nil {
		return "", err
	}
	credJSON, err := cred.Marshal()
	if err != nil {
		return "", err
	}
	if _, err := d.s.Pool.Exec(ctx,
		`INSERT INTO api_keys (tenant_id, account_id, login, name, key_prefix, cred)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, accountID, login, name, prefix, credJSON); err != nil {
		return "", err
	}
	return "omk_" + prefix + "_" + secret, nil
}

// AuthenticateAPIKey verifies a bearer API key and returns the tenant scope,
// principal, and account id it acts as. Token form omk_<prefix>_<secret>: lookup
// by the indexed prefix among non-revoked keys, then constant-time verify the
// secret. Failure is uniform (does not leak key existence).
func (d *Directory) AuthenticateAPIKey(ctx context.Context, token string) (directory.TenantScope, directory.Principal, int64, error) {
	fail := fmt.Errorf("authentication failed")
	prefix, secret, ok := parseAPIKeyToken(token)
	if !ok {
		return nil, directory.Principal{}, 0, fail
	}
	var (
		keyID, tenantID, accountID int64
		login                      string
		credJSON                   []byte
	)
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, account_id, login, cred FROM api_keys
		 WHERE key_prefix=$1 AND revoked_at IS NULL`, prefix).
		Scan(&keyID, &tenantID, &accountID, &login, &credJSON)
	if err == pgx.ErrNoRows {
		// Match the cost of a real verify so an unknown key prefix can't be
		// distinguished by timing.
		auth.VerifyAPIKeyDummy(secret)
		return nil, directory.Principal{}, 0, fail
	}
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	if !auth.VerifyAPIKey(credJSON, secret) {
		return nil, directory.Principal{}, 0, fail
	}
	ts, err := d.tenantScope(ctx, tenantID)
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	_, _ = d.s.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id=$1`, keyID)
	return ts, directory.Principal{TenantID: tenantID, Login: login}, accountID, nil
}

// newAPIKeyToken generates a random (prefix, secret) pair: prefix is a short
// public lookup selector, secret is the high-entropy half that is hashed.
func newAPIKeyToken() (prefix, secret string, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 24) // 192-bit secret
	if _, err = rand.Read(pb); err != nil {
		return "", "", err
	}
	if _, err = rand.Read(sb); err != nil {
		return "", "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(pb)), strings.ToLower(enc.EncodeToString(sb)), nil
}

// parseAPIKeyToken splits an omk_<prefix>_<secret> token.
func parseAPIKeyToken(token string) (prefix, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, "omk_")
	if !found {
		return "", "", false
	}
	prefix, secret, found = strings.Cut(rest, "_")
	if !found || prefix == "" || secret == "" {
		return "", "", false
	}
	return prefix, secret, true
}

func (d *Directory) tenantScope(ctx context.Context, tenantID int64) (*tenantScope, error) {
	var ti directory.TenantInfo
	var quota *int64
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, name, quota_bytes FROM tenants WHERE id=$1`, tenantID).
		Scan(&ti.ID, &ti.Name, &quota)
	if err != nil {
		return nil, err
	}
	if quota != nil {
		ti.QuotaBytes = *quota
	}
	return &tenantScope{s: d.s, info: ti}, nil
}

// ResolveInbound is the only unauthenticated resolver: domain -> tenant ->
// account, returning a delivery-only handle.
func (d *Directory) ResolveInbound(ctx context.Context, addr smtp.Path) (directory.InboundTarget, error) {
	var accID, tenantID int64
	var isAlias bool
	err := d.s.Pool.QueryRow(ctx,
		`SELECT a.account_id, a.tenant_id, a.is_alias
		 FROM addresses a
		 JOIN domains d ON d.id = a.domain_id
		 WHERE d.domain=$1 AND a.localpart=$2 AND NOT d.disabled`,
		addr.IPDomain.Domain.Name(), string(addr.Localpart)).
		Scan(&accID, &tenantID, &isAlias)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such recipient")
	}
	if err != nil {
		return nil, err
	}
	var name string
	if err := d.s.Pool.QueryRow(ctx, `SELECT name FROM accounts WHERE id=$1`, accID).Scan(&name); err != nil {
		return nil, err
	}
	var quota *int64
	var tname string
	_ = d.s.Pool.QueryRow(ctx, `SELECT name, quota_bytes FROM tenants WHERE id=$1`, tenantID).Scan(&tname, &quota)
	ti := directory.TenantInfo{ID: tenantID, Name: tname}
	if quota != nil {
		ti.QuotaBytes = *quota
	}
	return &inboundTarget{acc: d.s.openAccount(accID, tenantID, name), tenant: ti, isAlias: isAlias}, nil
}

// tenantScope is a capability bound to one tenant.
type tenantScope struct {
	s    *Store
	info directory.TenantInfo
}

func (t *tenantScope) Tenant() directory.TenantInfo { return t.info }

func (t *tenantScope) Account(ctx context.Context, name string) (store.Account, error) {
	var id int64
	err := t.s.Pool.QueryRow(ctx,
		`SELECT id FROM accounts WHERE tenant_id=$1 AND name=$2`, t.info.ID, name).Scan(&id)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such account")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(id, t.info.ID, name), nil
}

// AccountForAddress resolves a tenant-owned email address to its account.
func (t *tenantScope) AccountForAddress(ctx context.Context, addr smtp.Path) (store.Account, error) {
	var accID int64
	var name string
	err := t.s.Pool.QueryRow(ctx,
		`SELECT a.account_id, acc.name
		 FROM addresses a
		 JOIN domains d ON d.id = a.domain_id
		 JOIN accounts acc ON acc.id = a.account_id
		 WHERE a.tenant_id=$1 AND d.domain=$2 AND a.localpart=$3`,
		t.info.ID, addr.IPDomain.Domain.Name(), string(addr.Localpart)).Scan(&accID, &name)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no account for address")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(accID, t.info.ID, name), nil
}

// AccountForID resolves an account by id within this tenant. The WHERE clause
// pins tenant_id, so an id from another tenant returns no row — isolation is
// structural, not a caller convention.
func (t *tenantScope) AccountForID(ctx context.Context, id int64) (store.Account, error) {
	var name string
	err := t.s.Pool.QueryRow(ctx,
		`SELECT name FROM accounts WHERE id=$1 AND tenant_id=$2`, id, t.info.ID).Scan(&name)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such account")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(id, t.info.ID, name), nil
}

func (t *tenantScope) Accounts(ctx context.Context) ([]store.Account, error) {
	rows, err := t.s.Pool.Query(ctx, `SELECT id, name FROM accounts WHERE tenant_id=$1`, t.info.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Account
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, t.s.openAccount(id, t.info.ID, name))
	}
	return out, rows.Err()
}

func (t *tenantScope) Domain(ctx context.Context, dom dns.Domain) (directory.Domain, error) {
	var d directory.Domain
	err := t.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, domain, disabled FROM domains WHERE tenant_id=$1 AND domain=$2`,
		t.info.ID, dom.Name()).Scan(&d.ID, &d.TenantID, new(string), &d.Disabled)
	if err == pgx.ErrNoRows {
		return directory.Domain{}, fmt.Errorf("no such domain")
	}
	if err != nil {
		return directory.Domain{}, err
	}
	d.Domain = dom
	return d, nil
}

func (t *tenantScope) Quota() directory.TenantQuota {
	var q directory.TenantQuota
	_ = t.s.Pool.QueryRow(context.Background(),
		`SELECT bytes_used, msg_count FROM quota_counters WHERE scope_type=0 AND scope_id=$1`,
		t.info.ID).Scan(&q.BytesUsed, &q.MsgCount)
	q.BytesLimit = t.info.QuotaBytes
	return q
}

// inboundTarget is the delivery-only capability for unauthenticated SMTP.
type inboundTarget struct {
	acc     *account
	tenant  directory.TenantInfo
	isAlias bool
}

func (it *inboundTarget) Deliver(ctx context.Context, m *store.Message, body store.BlobReader) ([]store.Change, error) {
	return it.acc.DeliverMailbox("Inbox", m, body)
}
func (it *inboundTarget) DeliverTo(ctx context.Context, mailbox string, m *store.Message, body store.BlobReader) ([]store.Change, error) {
	return it.acc.DeliverMailbox(mailbox, m, body)
}
func (it *inboundTarget) AccountID() int64             { return it.acc.ID() }
func (it *inboundTarget) Tenant() directory.TenantInfo { return it.tenant }
func (it *inboundTarget) IsAlias() bool                { return it.isAlias }
func (it *inboundTarget) Rejected(reason string) error { return nil }
