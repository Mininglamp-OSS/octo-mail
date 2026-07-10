// Package inbound performs message authentication on received mail — SPF, DKIM,
// DMARC alignment, iprev, and DNSBL — reusing the protocol libraries verbatim
// (no reimplementation of the algorithms). It produces the header prefix
// (Received + Authentication-Results) that octo-mail stores in the DB alongside the
// message (never rewriting the on-disk body), exactly the intended convention.
//
// The resolver is injectable so tests drive it with dns.MockResolver and real
// SMTP clients; production passes dns.StrictResolver (DNSSEC-aware).
package inbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/iprev"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
)

// Session carries the per-connection facts needed for authentication.
type Session struct {
	RemoteIP    net.IP
	HelloDomain dns.IPDomain // EHLO/HELO argument
	MailFrom    smtp.Path    // SMTP MAIL FROM (may be empty for DSNs)
	LocalIP     net.IP
	Hostname    dns.Domain // this server's hostname (for Received/by + AR hostname)
	TLS         bool       // whether the SMTP session used TLS
	SMTPUTF8    bool
}

// Result is the outcome of authenticating one message.
type Result struct {
	SPF         spf.Status
	SPFDomain   dns.Domain
	DKIM        []dkim.Result
	DMARC       dmarc.Result
	IPRev       iprev.Status
	DNSBL       dnsbl.Status // worst status across configured zones
	DNSBLZone   string       // zone that listed the IP, if any
	AuthResults message.AuthResults
}

// Authenticator runs the inbound checks. Zero DNSBLZones disables DNSBL.
type Authenticator struct {
	Resolver   dns.Resolver
	DNSBLZones []dns.Domain
}

// Authenticate runs SPF (on the envelope), DKIM (on the message), DMARC
// alignment (From-header vs SPF/DKIM), iprev, and DNSBL. rawMsg must be the
// full RFC822 message. It returns the results and never errors on a failed
// check — failures are recorded as statuses, which is what the caller stores
// and uses to decide accept/reject/junk.
func (a *Authenticator) Authenticate(ctx context.Context, sess Session, rawMsg []byte) (Result, error) {
	var res Result
	res.AuthResults = message.AuthResults{Hostname: sess.Hostname.ASCII}

	// iprev (reverse-forward DNS on the client IP).
	if sess.RemoteIP != nil {
		ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, name, names, _, err := iprev.Lookup(ictx, a.Resolver, sess.RemoteIP)
		cancel()
		res.IPRev = st
		_ = err
		rev := name
		if rev == "" && len(names) > 0 {
			rev = names[0]
		}
		res.AuthResults.Methods = append(res.AuthResults.Methods, message.AuthMethod{
			Method: "iprev", Result: string(st),
			Props: []message.AuthProp{message.MakeAuthProp("policy", "iprev", sess.RemoteIP.String(), false, "")},
		})
		_ = rev
	}

	// SPF on the SMTP envelope.
	spfArgs := spf.Args{
		RemoteIP:          sess.RemoteIP,
		MailFromLocalpart: sess.MailFrom.Localpart,
		MailFromDomain:    sess.MailFrom.IPDomain.Domain,
		HelloDomain:       sess.HelloDomain,
		LocalIP:           sess.LocalIP,
		LocalHostname:     sess.Hostname,
	}
	var spfIdentity *dns.Domain
	if sess.RemoteIP != nil && (spfArgs.MailFromDomain.ASCII != "" || spfArgs.HelloDomain.Domain.ASCII != "") {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		recv, spfDom, _, _, err := spf.Verify(sctx, nil, a.Resolver, spfArgs)
		cancel()
		res.SPF = recv.Result
		res.SPFDomain = spfDom
		if err == nil && recv.Result == spf.StatusPass {
			d := spfDom
			spfIdentity = &d
		}
		res.AuthResults.Methods = append(res.AuthResults.Methods, message.AuthMethod{
			Method: "spf", Result: string(recv.Result),
			Props: []message.AuthProp{message.MakeAuthProp("smtp", "mailfrom", spfMailFrom(sess.MailFrom), true, "")},
		})
	}

	// DKIM on the message.
	dkimResults, err := dkim.Verify(ctx, nil, a.Resolver, sess.SMTPUTF8, func(*dkim.Sig) error { return nil }, byteReaderAt(rawMsg), false)
	if err == nil {
		res.DKIM = dkimResults
		for _, r := range dkimResults {
			m := message.AuthMethod{Method: "dkim", Result: string(r.Status)}
			if r.Sig != nil {
				m.Props = []message.AuthProp{message.MakeAuthProp("header", "d", r.Sig.Domain.ASCII, true, "")}
			}
			res.AuthResults.Methods = append(res.AuthResults.Methods, m)
		}
	}

	// DMARC alignment, keyed on the From-header domain.
	if fromDom, ok := fromDomain(rawMsg); ok {
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, dmarcResult := dmarc.Verify(dctx, nil, a.Resolver, fromDom, res.DKIM, res.SPF, spfIdentity, true)
		cancel()
		res.DMARC = dmarcResult
		res.AuthResults.Methods = append(res.AuthResults.Methods, message.AuthMethod{
			Method: "dmarc", Result: string(dmarcResult.Status),
			Props: []message.AuthProp{message.MakeAuthProp("header", "from", fromDom.ASCII, true, "")},
		})
	}

	// DNSBL on the client IP.
	if sess.RemoteIP != nil {
		for _, zone := range a.DNSBLZones {
			bctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			st, _, err := dnsbl.Lookup(bctx, nil, a.Resolver, zone, sess.RemoteIP)
			cancel()
			if err != nil {
				continue
			}
			if st == dnsbl.StatusFail {
				res.DNSBL = st
				res.DNSBLZone = zone.ASCII
				break
			}
		}
	}

	return res, nil
}

// Prefix builds the header block to store before the message body: a Received
// header plus the Authentication-Results header. This is prepended on read
// (MsgPrefix), never written into the immutable blob.
func (a *Authenticator) Prefix(sess Session, res Result, rcptTo string) []byte {
	var b strings.Builder

	// Received header.
	from := ""
	if len(sess.HelloDomain.IP) > 0 {
		from = smtp.AddressLiteral(sess.HelloDomain.IP)
	} else {
		from = sess.HelloDomain.Domain.ASCII
	}
	if sess.RemoteIP != nil {
		from += " (" + smtp.AddressLiteral(sess.RemoteIP) + ")"
	}
	with := "ESMTP"
	if sess.TLS {
		with = "ESMTPS"
	}
	b.WriteString("Received: from " + from + " by " + sess.Hostname.ASCII +
		" via tcp with " + with)
	if rcptTo != "" {
		b.WriteString("\r\n\tfor <" + rcptTo + ">;")
	} else {
		b.WriteString(";")
	}
	b.WriteString("\r\n\t" + time.Now().Format(message.RFC5322Z) + "\r\n")

	// Authentication-Results header.
	b.WriteString(res.AuthResults.Header())
	return []byte(b.String())
}

// --- helpers ---

func spfMailFrom(p smtp.Path) string {
	if p.IPDomain.Domain.ASCII == "" {
		return ""
	}
	return string(p.Localpart) + "@" + p.IPDomain.Domain.ASCII
}

// fromDomain parses the From-header domain from the raw message for DMARC.
func fromDomain(raw []byte) (dns.Domain, bool) {
	addr, _, _, err := message.From(nil, false, byteReaderAt(raw), nil)
	if err != nil {
		return dns.Domain{}, false
	}
	if addr.Domain.ASCII == "" {
		return dns.Domain{}, false
	}
	return addr.Domain, true
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// NormalizeEOL rewrites line endings to canonical CRLF: a bare LF (not preceded
// by CR) becomes CRLF, and a bare CR (not followed by LF) becomes CRLF. Inbound
// message scanners (header/body split, per-line header parsing) assume CRLF; a
// message that arrives with bare-LF endings would otherwise collapse into one
// unparseable blob and silently defeat ruleset/forward/subjectpass/auto-reply
// detection. Normalizing first makes those scanners robust regardless of the
// sender's line-ending discipline. Returns the input unchanged when already CRLF.
func NormalizeEOL(b []byte) []byte {
	if !bytes.ContainsAny(b, "\r\n") {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch c {
		case '\r':
			// Emit CRLF; consume a following LF so CRLF stays a single break.
			out = append(out, '\r', '\n')
			if i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
		case '\n':
			out = append(out, '\r', '\n')
		default:
			out = append(out, c)
		}
	}
	return out
}
