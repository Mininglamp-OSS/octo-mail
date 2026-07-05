package submit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

// AccountOpener opens an account handle by id (satisfied by postgres.Store via
// OpenAccountForTest-style access; production uses the directory). Kept as a
// narrow interface so the DSN generator doesn't depend on the whole store.
type AccountOpener interface {
	OpenAccountByID(id, tenantID int64, name string) store.Account
	AccountName(ctx context.Context, id int64) (string, error)
}

// DSNGenerator builds a bounce (DSN) for a permanently-failed outbound message
// and delivers it back into the sending account's Inbox — closing the loop so a
// sender learns of non-delivery. Reuses the dsn package for RFC 3464 format.
type DSNGenerator struct {
	Opener   AccountOpener
	Hostname dns.Domain // reporting MTA / DSN From domain
	// Blob, if set, lets the generator include the original message in the DSN when
	// the sender requested RET=FULL (RFC 3461). When nil, DSNs never include the
	// original body (headers-only behavior, as before).
	Blob blob.Store
}

// Generate composes and delivers a permanent-failure (bounce) DSN for a failed
// queue message.
func (g *DSNGenerator) Generate(ctx context.Context, m queue.Msg) error {
	return g.generate(ctx, m, dsn.Failed)
}

// GenerateDelayed composes and delivers a "still trying" delayed-delivery warning
// DSN — the message is not yet failed, but delivery has been retried enough times
// to warrant notifying the sender (RFC 3464 action=delayed). Mirrors mox's
// deliverDSNDelay.
func (g *DSNGenerator) GenerateDelayed(ctx context.Context, m queue.Msg) error {
	return g.generate(ctx, m, dsn.Delayed)
}

// dsnWanted reports whether a DSN of the given action should be sent given the
// sender's RFC 3461 NOTIFY request. An empty NOTIFY means the SMTP default
// (failures and delays are reported). NEVER suppresses everything; otherwise the
// action must be explicitly listed (FAILURE for a bounce, DELAY for a warning).
func dsnWanted(notify string, action dsn.Action) bool {
	if notify == "" {
		return true // default: report failures and delays
	}
	toks := strings.Split(strings.ToUpper(notify), ",")
	has := func(want string) bool {
		for _, t := range toks {
			if strings.TrimSpace(t) == want {
				return true
			}
		}
		return false
	}
	if has("NEVER") {
		return false
	}
	switch action {
	case dsn.Delayed:
		return has("DELAY")
	default: // dsn.Failed
		return has("FAILURE")
	}
}

func (g *DSNGenerator) generate(ctx context.Context, m queue.Msg, action dsn.Action) error {
	// Double-bounce guard: a message with a null return-path (empty MailFrom) is
	// itself a bounce/notification. RFC 3464 §6: never send a DSN for a message
	// whose envelope sender is <>, to prevent mail loops. Retire cleanly (nil).
	if m.MailFrom == "" {
		return nil
	}
	// Honor the sender's NOTIFY request (RFC 3461): a NEVER (or a list omitting this
	// action) suppresses the DSN.
	if !dsnWanted(m.Notify, action) {
		return nil
	}
	rcpt, err := smtp.ParseAddress(m.RcptTo)
	if err != nil {
		return fmt.Errorf("parse failed recipient: %w", err)
	}
	sender, err := smtp.ParseAddress(m.MailFrom)
	if err != nil {
		return fmt.Errorf("parse sender: %w", err)
	}

	subject, textBody, status := "", "", ""
	switch action {
	case dsn.Delayed:
		subject = "Delivery is delayed: still trying to deliver your message"
		textBody = fmt.Sprintf("Delivery to the following recipient has been delayed:\n\n    %s\n\nThe server will keep trying to deliver the message. You do not need to resend it.\n", m.RcptTo)
		status = "4.0.0"
	default: // dsn.Failed
		subject = "Mail delivery failed: returning message to sender"
		textBody = fmt.Sprintf("Delivery to the following recipient failed permanently:\n\n    %s\n\nThe message could not be delivered after repeated attempts.\n", m.RcptTo)
		status = "5.0.0"
	}

	recip := dsn.Recipient{
		FinalRecipient: rcpt.Path(),
		Action:         action,
		Status:         status,
	}
	// Echo the original recipient (RFC 3461 ORCPT), if the sender supplied one.
	if orcpt, ok := parseORCPT(m.ORcpt); ok {
		recip.OriginalRecipient = orcpt
	}

	msg := &dsn.Message{
		From:               smtp.Path{Localpart: "postmaster", IPDomain: dns.IPDomain{Domain: g.Hostname}},
		To:                 sender.Path(),
		Subject:            subject,
		MessageID:          fmt.Sprintf("<dsn-%d-%s@%s>", m.ID, action, g.Hostname.ASCII),
		TextBody:           textBody,
		ReportingMTA:       g.Hostname.ASCII,
		OriginalEnvelopeID: m.EnvID, // RFC 3461 ENVID echoed back
		ArrivalDate:        time.Now(),
		Recipients:         []dsn.Recipient{recip},
	}
	// RET (RFC 3461): FULL or HDRS both request the original be returned in the
	// DSN. The reused mox dsn library includes only the original *headers* in its
	// third MIME part (full-body inclusion is a library limitation), so FULL and
	// HDRS behave identically here; an unset RET omits the original entirely.
	// Requires a blob store to fetch the original.
	if ret := strings.ToUpper(m.Ret); (ret == "FULL" || ret == "HDRS") && g.Blob != nil {
		if orig := g.readOriginal(ctx, m); orig != nil {
			msg.Original = orig
		}
	}
	log := mlog.New("submit-dsn", nil)
	raw, err := msg.Compose(log, false)
	if err != nil {
		return fmt.Errorf("composing DSN: %w", err)
	}

	// Deliver the DSN into the sending account's Inbox.
	acc := g.Opener.OpenAccountByID(m.AccountID, m.TenantID, "")
	defer acc.Close()
	sm := &store.Message{}
	_, err = acc.DeliverMailbox("Inbox", sm, blobReader(raw))
	return err
}

// readOriginal fetches the original message body from the blob store for a
// RET=FULL DSN. Returns nil on any error (the DSN is still sent, just without the
// original attached).
func (g *DSNGenerator) readOriginal(ctx context.Context, m queue.Msg) []byte {
	br, err := g.Blob.Open(ctx, m.TenantID, blob.Ref(m.BlobRef))
	if err != nil {
		return nil
	}
	defer br.Close()
	b, err := io.ReadAll(br)
	if err != nil {
		return nil
	}
	return b
}

// parseORCPT decodes an RFC 3461 ORCPT value ("addr-type;addr", typically
// "rfc822;user@domain") into an smtp.Path. Returns ok=false if it can't.
func parseORCPT(orcpt string) (smtp.Path, bool) {
	if orcpt == "" {
		return smtp.Path{}, false
	}
	v := orcpt
	if _, rest, ok := strings.Cut(orcpt, ";"); ok {
		v = rest
	}
	addr, err := smtp.ParseAddress(strings.TrimSpace(v))
	if err != nil {
		return smtp.Path{}, false
	}
	return addr.Path(), true
}

// blobReader adapts a byte slice to store.BlobReader.
func blobReader(b []byte) store.BlobReader {
	return &bytesReader{Reader: bytes.NewReader(b), size: int64(len(b))}
}

type bytesReader struct {
	*bytes.Reader
	size int64
}

func (b *bytesReader) Size() int64  { return b.size }
func (b *bytesReader) Close() error { return nil }
