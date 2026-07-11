package acme

// export_test.go exposes internals to the external acme_test package for tests that
// need to exercise the leader-gated cache wrapper directly.

import "github.com/mjl-/autocert"

// AutocertCacheForTest returns the (leader-gated) cache installed on the underlying
// autocert manager — the one autocert itself writes through. Test-only.
func (m *Manager) AutocertCacheForTest() autocert.Cache {
	return m.m.Manager.Cache
}
