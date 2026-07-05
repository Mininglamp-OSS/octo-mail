// Package webui serves octo-mail's minimal HTML webmail — the product-layer surface
// for end users, a small strict-TypeScript client
// (assets/app.ts, compiled to committed assets/app.js) embedded in the binary
// and served over HTTP. The client drives the existing JMAP API (login →
// Email/query → Email/get → upload+Email/set+EmailSubmission), so the browser
// needs no external mail client.
//
// This is intentionally a minimal subset. It proves the
// product layer end to end: a browser can sign in and read/send mail.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/index.html assets/app.js
var assets embed.FS

// Handler returns an http.Handler serving the webmail SPA at /webmail/.
// index.html is served at /webmail/ and /webmail; app.js at /webmail/app.js.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // embedded FS is static; a failure here is a build bug
	}
	fileServer := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	mux.HandleFunc("/webmail", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/webmail/", http.StatusFound)
	})
	mux.Handle("/webmail/", http.StripPrefix("/webmail/", fileServer))
	return mux
}
