// Package directory is the identity object graph and the root of tenant
// isolation. Isolation is structural, not a per-query discipline: the only way
// to obtain an Account handle is to navigate from a TenantScope you were granted
// (via authentication) or an InboundTarget (via inbound address resolution).
// There is deliberately no id-taking, tenant-crossing accessor anywhere — a
// handler holding tenant A's scope has no reference through which to name tenant
// B's objects. This replaces a flat, global Account(name) /
// LookupAddress, where isolation was "pass the right name".
package directory

import (
	"context"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// TenantInfo identifies a tenant. Quota/limits hang off it.
type TenantInfo struct {
	ID         int64
	Name       string
	QuotaBytes int64
}

// Credential is an authentication secret (SCRAM exchange, password, TLS pubkey).
// Concrete types live in the auth path; Directory only verifies.
type Credential any

// PasswordCredential is a plaintext password presented for verification against
// the principal's stored argon2id hash. Network entry points must pass this;
// a nil Credential is resolve-only and reserved for trusted internal callers.
type PasswordCredential string

// Principal is an authenticated identity within a tenant.
type Principal struct {
	ID       int64
	TenantID int64
	Login    string
}

// Directory is the entry point. It yields only tenant-scoped capabilities.
type Directory interface {
	// AuthenticatePrincipal verifies a login and returns a scope bound to
	// exactly one tenant.
	AuthenticatePrincipal(ctx context.Context, login string, cred Credential) (TenantScope, Principal, error)

	// AuthenticateAPIKey verifies a bearer API key (form omk_<prefix>_<secret>)
	// and returns the tenant scope, principal, and the account id the key acts as.
	// It is the account-scoped equivalent of a login, used by the JMAP/WebAPI
	// HTTP surfaces for agent-facing Bearer auth.
	AuthenticateAPIKey(ctx context.Context, token string) (TenantScope, Principal, int64, error)

	// ResolveInbound is the ONLY unauthenticated resolver. Inbound SMTP arrives
	// at a domain with no principal; this returns a delivery-only handle bound
	// to a single account. It cannot be widened to read or list the mailbox.
	ResolveInbound(ctx context.Context, addr smtp.Path) (InboundTarget, error)
}

// SCRAMVerifier is a stored SCRAM-SHA-256 salted-password verifier, returned by
// a SCRAMAuthenticator so the protocol layer can run the SASL exchange without
// the plaintext password ever being present.
type SCRAMVerifier struct {
	Salt           []byte
	SaltedPassword []byte
	Iterations     int
}

// SCRAMAuthenticator is optionally implemented by a Directory to support the
// SASL SCRAM-SHA-256 mechanism. The protocol server looks up the verifier,
// drives the challenge/response exchange itself (proving the client knows the
// password without transmitting it), then calls ScopeForLogin to obtain the
// tenant-bound capability. ScopeForLogin performs no credential check — it is
// only called after the SCRAM proof has been verified.
type SCRAMAuthenticator interface {
	LookupSCRAM(ctx context.Context, login string) (SCRAMVerifier, error)
	ScopeForLogin(ctx context.Context, login string) (TenantScope, Principal, error)
}

// TenantScope is a capability scoped to one tenant. Every accessor returns only
// this tenant's objects; there is no method to reach another tenant.
type TenantScope interface {
	Tenant() TenantInfo
	Account(ctx context.Context, name string) (store.Account, error)
	// AccountForAddress resolves one of this tenant's email addresses to the
	// owning account (address localpart may differ from account name). Used by
	// submission auth, where the login is an email address.
	AccountForAddress(ctx context.Context, addr smtp.Path) (store.Account, error)
	Accounts(ctx context.Context) ([]store.Account, error)
	Domain(ctx context.Context, d dns.Domain) (Domain, error)
	Quota() TenantQuota
}

// Domain is a tenant-owned domain.
type Domain struct {
	ID       int64
	TenantID int64
	Domain   dns.Domain
	Disabled bool
}

// TenantQuota reports per-tenant usage/limits (a projection of the log).
type TenantQuota struct {
	BytesUsed  int64
	BytesLimit int64
	MsgCount   int64
}

// InboundTarget is the minimum capability for unauthenticated delivery: append
// to one account, nothing else. It carries the tenant id for reputation
// attribution but exposes no way to read the mailbox or reach siblings.
type InboundTarget interface {
	Deliver(ctx context.Context, m *store.Message, body store.BlobReader) ([]store.Change, error)
	// DeliverTo appends to a named mailbox (e.g. "Junk"), creating it if needed.
	// Used by the receiver to route spam-classified mail to the Junk mailbox.
	DeliverTo(ctx context.Context, mailbox string, m *store.Message, body store.BlobReader) ([]store.Change, error)
	// AccountID identifies the destination account, for per-account junk
	// classification/training (not a capability to reach other accounts).
	AccountID() int64
	Tenant() TenantInfo
	IsAlias() bool
	Rejected(reason string) error
}
