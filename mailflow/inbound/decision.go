// Package inbound's decision engine combines greylisting, per-recipient sender
// reputation, and bayesian junk scoring into a single inbound verdict — the
// octo-mail equivalent of the smtpserver/analyze.go + reputation.go, implemented
// on the Postgres substrate rather than bstore. The verdict is computed AFTER
// DATA (content available) so a spammy first contact can be rejected at SMTP
// time (5xx) or greylisted (4xx) instead of always being accepted and filed.
package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/subjectpass"
)

// Verdict is the inbound decision for one message.
type Verdict int

const (
	Accept     Verdict = iota // deliver to Inbox
	AcceptJunk                // deliver to Junk mailbox
	Defer                     // temporary 4xx (greylist) — client should retry
	Reject                    // permanent 5xx
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "accept"
	case AcceptJunk:
		return "junk"
	case Defer:
		return "defer"
	case Reject:
		return "reject"
	}
	return "unknown"
}

// Decision carries the verdict plus a human-readable reason (for logs/AR).
type Decision struct {
	Verdict Verdict
	Reason  string
	// Mailbox, when non-empty, overrides the destination mailbox (a ruleset match
	// forcing delivery to e.g. "Lists"). Empty means the default (Inbox/Junk).
	Mailbox string
	// Challenge, when non-empty on a Defer verdict, is a subjectpass phrase the
	// caller should include in the 4xx so a legitimate sender can retry with it in
	// the Subject and pass.
	Challenge string
}

// Decider makes inbound accept/defer/reject decisions. It is safe to leave any
// knob at zero for sensible defaults.
type Decider struct {
	Pool *pgxpool.Pool

	// GreylistDelay is how long a first-seen triplet is deferred (default 5m).
	GreylistDelay time.Duration
	// GreylistEnabled turns greylisting on. Off by default (opt-in) because it
	// adds delivery latency for first contacts.
	GreylistEnabled bool

	// JunkThreshold: probability >= this is spam (default 0.95).
	JunkThreshold float64
	// RejectThreshold: probability >= this is rejected outright (default 0.999,
	// i.e. only near-certain spam is 5xx'd; the rest goes to Junk).
	RejectThreshold float64

	// TrustedHamCount: a sender domain with at least this many accepted (ham)
	// messages and no junk skips content-based rejection (default 3).
	TrustedHamCount int64

	// SubjectPassKey, when non-empty, enables subjectpass (subjectpass): a
	// message that would be rejected on content is instead deferred with a
	// challenge — the sender may retry with a signed token in the Subject, which
	// is then accepted. Bypasses reputation/content rejection for legitimate
	// senders willing to reply. Empty = disabled.
	SubjectPassKey []byte
	// SubjectPassPeriod is how long a subjectpass token is valid (default 12h).
	SubjectPassPeriod time.Duration
}

// ClassifyFunc returns the bayesian spam probability and significance for a
// message body, for the recipient account. Wired to junkfilter.Manager.Classify.
type ClassifyFunc func(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error)

func (d *Decider) greylistDelay() time.Duration {
	if d.GreylistDelay > 0 {
		return d.GreylistDelay
	}
	return 5 * time.Minute
}
func (d *Decider) junkThreshold() float64 {
	if d.JunkThreshold > 0 {
		return d.JunkThreshold
	}
	return 0.95
}
func (d *Decider) rejectThreshold() float64 {
	if d.RejectThreshold > 0 {
		return d.RejectThreshold
	}
	return 0.999
}

// adaptiveJunkThreshold adjusts the base junk threshold by the sender domain's
// history: a domain with more ham than junk earns a higher (more lenient)
// threshold; a mostly-junk domain a lower (stricter) one. The result is clamped
// to (0.5, rejectThreshold) so it never becomes trivial or crosses into reject.
func (d *Decider) adaptiveJunkThreshold(ham, junk int64) float64 {
	base := d.junkThreshold()
	total := ham + junk
	if total < 5 {
		return base // not enough history to adapt
	}
	hamRatio := float64(ham) / float64(total)
	// Shift up to ±0.1 around base: hamRatio 1.0 → +0.1 (lenient), 0.0 → -0.1.
	adj := (hamRatio - 0.5) * 0.2
	thr := base + adj
	if lo := 0.5; thr < lo {
		thr = lo
	}
	if hi := d.rejectThreshold() - 0.001; thr > hi {
		thr = hi
	}
	return thr
}
func (d *Decider) trustedHam() int64 {
	if d.TrustedHamCount > 0 {
		return d.TrustedHamCount
	}
	return 3
}

// Decide computes the inbound verdict for a message to accountID from
// senderDomain/clientIP, given the auth result and a junk classifier. Order:
//  1. authentication-based hard reject (DMARC handled by caller earlier);
//  2. reputation: enough ham + no junk → Accept (trusted, skip content checks);
//     enough junk + no ham → Reject (known-bad sender);
//  3. greylist first-seen triplet → Defer;
//  4. content (bayesian): near-certain spam → Reject, spam → AcceptJunk;
//  5. otherwise Accept.
func (d *Decider) Decide(ctx context.Context, accountID int64, senderDomain string, clientIP net.IP, raw []byte, classify ClassifyFunc) Decision {
	// 1. Rulesets: a per-account header match can force a destination mailbox and
	//    (by default) accept unconditionally, bypassing reputation/content checks.
	if rs, ok := d.matchRuleset(ctx, accountID, raw); ok {
		if rs.forceAccept {
			return Decision{Verdict: Accept, Reason: "ruleset", Mailbox: rs.mailbox}
		}
		// Forwarded messages (the analyze design): the forwarding server's SPF/DMARC
		// and IP reputation don't reflect the true origin, so skip reputation- and
		// content-based rejection — deliver to the ruleset's mailbox (or Inbox).
		if rs.isForward {
			mb := rs.mailbox
			return Decision{Verdict: Accept, Reason: "forwarded", Mailbox: mb}
		}
		// Non-force ruleset: run the checks once; on accept, route to the
		// ruleset's mailbox. Return the single result either way — never re-run
		// decideCore (it mutates greylist state and re-classifies).
		dec := d.decideCore(ctx, accountID, senderDomain, clientIP, raw, classify)
		if dec.Verdict == Accept || dec.Verdict == AcceptJunk {
			dec.Mailbox = rs.mailbox
		}
		return dec
	}
	return d.decideCore(ctx, accountID, senderDomain, clientIP, raw, classify)
}

// decideCore is the reputation + greylist + content pipeline, with subjectpass
// applied to would-be content rejections.
func (d *Decider) decideCore(ctx context.Context, accountID int64, senderDomain string, clientIP net.IP, raw []byte, classify ClassifyFunc) Decision {
	// 2. Reputation shortcut.
	ham, junk := d.reputation(ctx, accountID, senderDomain)
	if ham >= d.trustedHam() && junk == 0 {
		return Decision{Verdict: Accept, Reason: "trusted-sender"}
	}
	if junk >= 3 && ham == 0 {
		return d.maybeSubjectPass(raw, Decision{Verdict: Reject, Reason: "known-bad-sender"})
	}

	// 3. Greylist first-seen triplets (only for not-yet-trusted senders).
	if d.GreylistEnabled {
		if deferred := d.greylist(ctx, accountID, senderDomain, clientIP); deferred {
			return Decision{Verdict: Defer, Reason: "greylisted"}
		}
	}

	// 4. Content-based bayesian scoring, with a per-domain adaptive junk threshold:
	//    a domain with a strong ham history gets a more lenient threshold (harder
	//    to file as junk), a mostly-junk domain a stricter one. Bounded so it never
	//    crosses the reject threshold or drops below 0.5.
	if classify != nil {
		prob, significant, _, err := classify(ctx, accountID, raw)
		if err == nil && significant {
			junkThr := d.adaptiveJunkThreshold(ham, junk)
			if prob >= d.rejectThreshold() {
				return d.maybeSubjectPass(raw, Decision{Verdict: Reject, Reason: "junk-content-strict"})
			}
			if prob >= junkThr {
				return Decision{Verdict: AcceptJunk, Reason: "junk-content"}
			}
		}
	}
	return Decision{Verdict: Accept, Reason: "clean"}
}

// maybeSubjectPass converts a Reject into either an Accept (when the message
// carries a valid subjectpass token in its Subject) or a Defer carrying a
// challenge phrase (so a legitimate sender can retry). If subjectpass is
// disabled, the original reject stands.
func (d *Decider) maybeSubjectPass(raw []byte, reject Decision) Decision {
	if len(d.SubjectPassKey) == 0 {
		return reject
	}
	// A valid token already present → accept.
	if err := subjectpass.Verify(nil, bytesReaderAt(raw), d.SubjectPassKey, d.subjectPassPeriod()); err == nil {
		return Decision{Verdict: Accept, Reason: "subjectpass-verified"}
	}
	// Otherwise issue a challenge the sender can echo in the Subject.
	from := subjectPassFrom(raw)
	token := subjectpass.Generate(nil, from, d.SubjectPassKey, timeNow())
	return Decision{Verdict: Defer, Reason: "subjectpass-challenge", Challenge: token}
}

func (d *Decider) subjectPassPeriod() time.Duration {
	if d.SubjectPassPeriod > 0 {
		return d.SubjectPassPeriod
	}
	return 12 * time.Hour
}

// reputation returns (ham, junk) counts for (account, senderDomain).
func (d *Decider) reputation(ctx context.Context, accountID int64, senderDomain string) (ham, junk int64) {
	_ = d.Pool.QueryRow(ctx,
		`SELECT ham_count, junk_count FROM inbound_reputation WHERE account_id=$1 AND sender_domain=$2`,
		accountID, senderDomain).Scan(&ham, &junk)
	return ham, junk
}

// RecordOutcome updates inbound reputation after a message is filed: ham=true if
// delivered to Inbox, false if to Junk. Called post-delivery.
func (d *Decider) RecordOutcome(ctx context.Context, accountID int64, senderDomain string, ham bool) error {
	col := "junk_count"
	if ham {
		col = "ham_count"
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO inbound_reputation (account_id, sender_domain, `+col+`) VALUES ($1,$2,1)
		 ON CONFLICT (account_id, sender_domain)
		 DO UPDATE SET `+col+` = inbound_reputation.`+col+` + 1, updated_at = now()`,
		accountID, senderDomain)
	return err
}

// greylist returns true if the triplet is first-seen (or still within the delay)
// and should be deferred. On a retry after the delay it records allowed_at and
// returns false. Subnet is /24 (v4) or /64 (v6).
func (d *Decider) greylist(ctx context.Context, accountID int64, senderDomain string, ip net.IP) bool {
	subnet := subnetOf(ip)
	// Compute the triplet's age in SQL (avoids Go/DB clock & timezone skew).
	var ageSecs float64
	var allowedAt *time.Time
	err := d.Pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (now()-first_seen)), allowed_at FROM greylist WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
		accountID, senderDomain, subnet).Scan(&ageSecs, &allowedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// First contact: record and defer.
		_, _ = d.Pool.Exec(ctx,
			`INSERT INTO greylist (account_id, sender_domain, client_subnet) VALUES ($1,$2,$3)
			 ON CONFLICT DO NOTHING`, accountID, senderDomain, subnet)
		return true
	}
	if err != nil {
		// On error, fail open (accept) rather than block mail.
		return false
	}
	if allowedAt != nil {
		return false // already passed greylisting
	}
	if ageSecs >= d.greylistDelay().Seconds() {
		now := time.Now()
		_, _ = d.Pool.Exec(ctx,
			`UPDATE greylist SET allowed_at=$4, count=count+1 WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
			accountID, senderDomain, subnet, now)
		return false
	}
	// Still within the delay window: keep deferring.
	_, _ = d.Pool.Exec(ctx,
		`UPDATE greylist SET count=count+1 WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
		accountID, senderDomain, subnet)
	return true
}

// subnetOf returns the greylisting subnet key for an IP (/24 v4, /64 v6).
func subnetOf(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ruleset is a matched per-account delivery rule.
type ruleset struct {
	mailbox     string
	forceAccept bool
	isForward   bool
}

// matchRuleset returns the first ruleset (by ord) whose header substring matches
// the message. It parses the message headers with the parser and does a
// case-insensitive substring test on the named header's value.
func (d *Decider) matchRuleset(ctx context.Context, accountID int64, raw []byte) (ruleset, bool) {
	rows, err := d.Pool.Query(ctx,
		`SELECT header_name, header_substr, mailbox, force_accept, is_forward FROM rulesets
		 WHERE account_id=$1 ORDER BY ord, id`, accountID)
	if err != nil {
		return ruleset{}, false
	}
	type rule struct {
		name, substr, mailbox string
		force                 bool
		forward               bool
	}
	var rules []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.name, &r.substr, &r.mailbox, &r.force, &r.forward); err != nil {
			rows.Close()
			return ruleset{}, false
		}
		rules = append(rules, r)
	}
	rows.Close()
	if len(rules) == 0 {
		return ruleset{}, false
	}
	hdrs := parseHeaders(raw)
	for _, r := range rules {
		v := hdrs[strings.ToLower(r.name)]
		if v != "" && strings.Contains(strings.ToLower(v), strings.ToLower(r.substr)) {
			return ruleset{mailbox: r.mailbox, forceAccept: r.force, isForward: r.forward}, true
		}
	}
	return ruleset{}, false
}

// parseHeaders extracts folded header name→value pairs from a raw message (only
// the header block; first value wins per name). Lowercased names as keys.
func parseHeaders(raw []byte) map[string]string {
	s := string(raw)
	end := strings.Index(s, "\r\n\r\n")
	if end < 0 {
		end = len(s)
	}
	head := s[:end]
	// Unfold continuation lines.
	head = strings.ReplaceAll(head, "\r\n\t", "\t")
	head = strings.ReplaceAll(head, "\r\n ", " ")
	out := map[string]string{}
	for _, line := range strings.Split(head, "\r\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if _, ok := out[name]; !ok {
			out[name] = val
		}
	}
	return out
}

// subjectPassFrom extracts a smtp.Address from the message From header for the
// subjectpass token (best-effort; zero address if unparseable).
func subjectPassFrom(raw []byte) smtp.Address {
	hdrs := parseHeaders(raw)
	from := hdrs["from"]
	if i := strings.LastIndexByte(from, '<'); i >= 0 {
		from = from[i+1:]
		from = strings.TrimSuffix(from, ">")
	}
	from = strings.TrimSpace(from)
	if addr, err := smtp.ParseAddress(from); err == nil {
		return addr
	}
	return smtp.Address{}
}

// bytesReaderAt adapts a byte slice to io.ReaderAt for subjectpass.Verify.
type bytesReaderAtT []byte

func (b bytesReaderAtT) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func bytesReaderAt(b []byte) bytesReaderAtT { return bytesReaderAtT(b) }

// timeNow is a package var for test substitution of the subjectpass timestamp.
var timeNow = time.Now
