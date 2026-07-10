package imapd

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// parseInternalDate parses an IMAP date-time ("02-Jan-2006 15:04:05 -0700") as
// used in APPEND. Returns the zero time when unparseable, so callers fall back
// to the delivery time.
func parseInternalDate(s string) time.Time {
	s = strings.TrimSpace(s)
	// RFC 3501 date-time uses a space-padded day ("_2"); also accept a
	// zero-padded day for lenient clients.
	for _, layout := range []string{"_2-Jan-2006 15:04:05 -0700", "02-Jan-2006 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// cmdCreate implements CREATE (RFC 3501) with the CREATE-SPECIAL-USE extension
// (RFC 6154): "CREATE <name> [USE (\Sent \Drafts ...)]" assigns special-use
// attributes to the new mailbox.
func (c *conn) cmdCreate(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)
	// Optional trailing "USE (...)" special-use list.
	var su store.SpecialUse
	if i := strings.LastIndex(strings.ToUpper(rest), "USE ("); i >= 0 {
		end := strings.IndexByte(rest[i:], ')')
		if end < 0 {
			c.no(tag, "malformed USE list")
			return
		}
		su = parseSpecialUse(rest[i+len("USE (") : i+end])
		rest = strings.TrimSpace(rest[:i])
	}
	name := normalizeMailbox(unquote(strings.TrimSpace(rest)))
	if name == "" {
		c.no(tag, "invalid mailbox name")
		return
	}
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		_, _, _, exists, err := c.acc.MailboxCreate(tx, name, su)
		if err != nil {
			return err
		}
		if exists {
			return errNo("mailbox already exists")
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	c.ok(tag, "CREATE completed")
}

// cmdDelete implements DELETE: remove a mailbox (must have no child mailboxes).
func (c *conn) cmdDelete(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	name := normalizeMailbox(unquote(strings.TrimSpace(args)))
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		mb, err := c.acc.MailboxFind(tx, name)
		if err != nil {
			return err
		}
		if mb == nil {
			return errNo("no such mailbox")
		}
		_, hasChildren, err := c.acc.MailboxDelete(c.ctx, tx, mb)
		if err != nil {
			return err
		}
		if hasChildren {
			return errNo("mailbox has children")
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	c.ok(tag, "DELETE completed")
}

// cmdRename implements RENAME.
func (c *conn) cmdRename(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	srcTok, dstTok := cut(strings.TrimSpace(args), " ")
	src := normalizeMailbox(unquote(strings.TrimSpace(srcTok)))
	dst := normalizeMailbox(unquote(strings.TrimSpace(dstTok)))
	if src == "" || dst == "" {
		c.no(tag, "invalid mailbox name")
		return
	}
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		mb, err := c.acc.MailboxFind(tx, src)
		if err != nil {
			return err
		}
		if mb == nil {
			return errNo("no such mailbox")
		}
		_, exists, notExists, err := c.acc.MailboxRename(tx, mb, dst, nil)
		if err != nil {
			return err
		}
		if notExists {
			return errNo("source mailbox does not exist")
		}
		if exists {
			return errNo("destination mailbox already exists")
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	c.ok(tag, "RENAME completed")
}

// cmdSubscribe / cmdUnsubscribe. Subscription state is a change-log entry; we
// accept both and record subscribe (unsubscribe is a no-op success in the
// compact core since LIST returns all mailboxes).
func (c *conn) cmdSubscribe(tag, args string, subscribe bool) {
	if !c.requireAuth(tag) {
		return
	}
	name := normalizeMailbox(unquote(strings.TrimSpace(args)))
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		mb, err := c.acc.MailboxFind(tx, name)
		if err != nil {
			return err
		}
		if mb == nil {
			return errNo("no such mailbox")
		}
		if subscribe {
			_, err = c.acc.SubscriptionEnsure(tx, name)
		} else {
			_, err = c.acc.SubscriptionRemove(tx, name)
		}
		return err
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	c.ok(tag, "completed")
}

// cmdAppend implements APPEND: save a client-supplied message into a mailbox
// (used for drafts, sent copies, migration). Reads a non-synchronizing literal
// "{n+}" or synchronizing "{n}" (to which we send a "+ " continuation).
func (c *conn) cmdAppend(tag, args string) {
	if !c.requireAuth(tag) {
		return
	}
	rest := strings.TrimSpace(args)
	mbTok, rest := cut(rest, " ")
	mailbox := normalizeMailbox(unquote(strings.TrimSpace(mbTok)))
	rest = strings.TrimSpace(rest)

	// One or more message appends follow (RFC 3502 MULTIAPPEND): each is an
	// optional flag list, an optional date-time, and a literal. We parse them
	// one at a time, reading the trailing bytes after each literal as the next
	// append's descriptor, until the command line ends.
	type pending struct {
		flags    []string
		received time.Time
		data     []byte
	}
	var appends []pending
	for {
		// Optional flag list "(...)".
		var flags []string
		if strings.HasPrefix(rest, "(") {
			end := strings.IndexByte(rest, ')')
			if end < 0 {
				c.no(tag, "bad flag list")
				return
			}
			flags = strings.Fields(rest[1:end])
			rest = strings.TrimSpace(rest[end+1:])
		}
		// Optional date-time "..." — honored as INTERNALDATE when parseable.
		var received time.Time
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end >= 0 {
				received = parseInternalDate(rest[1 : end+1])
				rest = strings.TrimSpace(rest[end+2:])
			}
		}
		// Message data: either CATENATE (a part list assembled server-side, RFC
		// 4469) or a plain literal.
		var data []byte
		if up := strings.ToUpper(rest); strings.HasPrefix(up, "CATENATE ") || up == "CATENATE" {
			assembled, remainder, err := c.readCatenate(strings.TrimSpace(rest[len("CATENATE"):]))
			if err != nil {
				c.no(tag, "CATENATE failed: "+err.Error())
				return
			}
			data = assembled
			rest = strings.TrimSpace(remainder)
			appends = append(appends, pending{flags: flags, received: received, data: data})
			if rest == "" {
				break
			}
			continue
		}
		// Literal: {n} or {n+}, optionally wrapped as UTF8 (<literal>) (RFC 6855).
		utf8Wrapped := false
		if up := strings.ToUpper(rest); strings.HasPrefix(up, "UTF8 (") {
			utf8Wrapped = true
			rest = strings.TrimSpace(rest[len("UTF8 ("):])
		}
		data, err := c.readLiteral(rest)
		if err != nil {
			c.no(tag, "expected message literal: "+err.Error())
			return
		}
		appends = append(appends, pending{flags: flags, received: received, data: data})

		// After the literal come either more appends on the same line or the
		// terminating CRLF (for UTF8-wrapped data, a closing ")" precedes it).
		// Read the rest of the line; if it is blank, we are done.
		line, _ := c.readLine()
		rest = strings.TrimSpace(line)
		if utf8Wrapped {
			rest = strings.TrimSpace(strings.TrimPrefix(rest, ")"))
		}
		if rest == "" {
			break
		}
	}

	// Persist all messages in a single transaction so MULTIAPPEND is atomic.
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		mb, err := c.acc.MailboxFind(tx, mailbox)
		if err != nil {
			return err
		}
		if mb == nil {
			nmb, _, _, _, e := c.acc.MailboxCreate(tx, mailbox, store.SpecialUse{})
			if e != nil {
				return e
			}
			mb = &nmb
		}
		for _, a := range appends {
			m := &store.Message{}
			applyFlags(m, "FLAGS", a.flags)
			if !a.received.IsZero() {
				m.Received = a.received
			}
			if _, e := c.acc.MessageAdd(tx, mb, m, newBytesBlob(a.data), store.AddOpts{}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		if err == store.ErrOverQuota {
			c.no(tag, "[OVERQUOTA] mailbox is full")
			return
		}
		c.no(tag, err.Error())
		return
	}
	c.ok(tag, "APPEND completed")
}

// cmdReplace implements REPLACE / UID REPLACE (RFC 8508): atomically append a new
// message to a target mailbox and expunge the referenced source message from the
// currently-selected mailbox. args: "<seq-or-uid> <mailbox> [(flags)] [\"date\"] {n}".
// Both operations run in one transaction, so a client never observes a window
// with zero or two copies.
func (c *conn) cmdReplace(tag, args string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	if c.readOnly {
		c.no(tag, "mailbox is read-only")
		return
	}
	rest := strings.TrimSpace(args)
	seqTok, rest := cut(rest, " ")
	seqTok = strings.TrimSpace(seqTok)
	rest = strings.TrimSpace(rest)
	mbTok, rest := cut(rest, " ")
	mailbox := normalizeMailbox(unquote(strings.TrimSpace(mbTok)))
	rest = strings.TrimSpace(rest)

	// Optional flag list "(...)".
	var flags []string
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			c.no(tag, "bad flag list")
			return
		}
		flags = strings.Fields(rest[1:end])
		rest = strings.TrimSpace(rest[end+1:])
	}
	// Optional date-time "..." — skip it.
	if strings.HasPrefix(rest, `"`) {
		end := strings.IndexByte(rest[1:], '"')
		if end >= 0 {
			rest = strings.TrimSpace(rest[end+2:])
		}
	}
	// Literal: {n} or {n+}.
	data, err := c.readLiteral(rest)
	if err != nil {
		c.no(tag, "expected message literal: "+err.Error())
		return
	}
	_, _ = c.readLine()

	m := &store.Message{}
	applyFlags(m, "FLAGS", flags)
	var expungedSeq uint32
	err = c.acc.Tx(c.ctx, func(tx store.Tx) error {
		// Resolve the source message in the selected mailbox.
		msgs, e := tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
		if e != nil {
			return e
		}
		var maxUID uint32
		if len(msgs) > 0 {
			maxUID = uint32(msgs[len(msgs)-1].UID)
		}
		var match func(uint32) bool
		if byUID {
			match = parseUIDSet(seqTok, maxUID)
		} else {
			match = parseUIDSet(seqTok, uint32(len(msgs)))
		}
		var src *store.Message
		for i := range msgs {
			var sel bool
			if byUID {
				sel = match(uint32(msgs[i].UID))
			} else {
				sel = match(uint32(i + 1))
			}
			if sel {
				src = &msgs[i]
				expungedSeq = uint32(i + 1)
				break
			}
		}
		if src == nil {
			return errNoSource
		}
		// Append the replacement into the target mailbox.
		mb, e := c.acc.MailboxFind(tx, mailbox)
		if e != nil {
			return e
		}
		if mb == nil {
			nmb, _, _, _, ce := c.acc.MailboxCreate(tx, mailbox, store.SpecialUse{})
			if ce != nil {
				return ce
			}
			mb = &nmb
		}
		if _, e := c.acc.MessageAdd(tx, mb, m, newBytesBlob(data), store.AddOpts{}); e != nil {
			return e
		}
		// Expunge the source in the same transaction (atomic replace).
		_, _, e = c.acc.MessageRemove(tx, 0, c.selected, store.RemoveOpts{Expunge: true}, *src)
		return e
	})
	if err != nil {
		if err == store.ErrOverQuota {
			c.no(tag, "[OVERQUOTA] mailbox is full")
			return
		}
		if err == errNoSource {
			c.no(tag, "source message not found")
			return
		}
		c.no(tag, err.Error())
		return
	}
	// Report the removal so the client's view stays consistent.
	if expungedSeq > 0 {
		c.writef("* %d EXPUNGE", expungedSeq)
	}
	c.ok(tag, "REPLACE completed")
}

// errNoSource marks a REPLACE whose referenced source message does not exist.
var errNoSource = errString("no source message")

type errString string

func (e errString) Error() string { return string(e) }

// selected mailbox, emitting untagged EXPUNGE responses (highest seq first per
// RFC, but clients accept ascending; we emit ascending by recomputed position).
func (c *conn) cmdExpunge(tag string, uidSet string, byUID bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	if c.readOnly {
		c.no(tag, "mailbox is read-only")
		return
	}
	var expunged []uint32
	var expungedUIDs []uint32
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		msgs, err := tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
		if err != nil {
			return err
		}
		var match func(uint32) bool
		if byUID && uidSet != "" {
			var maxUID uint32
			if len(msgs) > 0 {
				maxUID = uint32(msgs[len(msgs)-1].UID)
			}
			match = parseUIDSet(uidSet, maxUID)
		}
		var toRemove []store.Message
		for i, m := range msgs {
			if !m.Deleted {
				continue
			}
			if match != nil && !match(uint32(m.UID)) {
				continue
			}
			toRemove = append(toRemove, m)
			expunged = append(expunged, uint32(i+1))
			expungedUIDs = append(expungedUIDs, uint32(m.UID))
		}
		if len(toRemove) == 0 {
			return nil
		}
		_, _, err = c.acc.MessageRemove(tx, 0, c.selected, store.RemoveOpts{Expunge: true}, toRemove...)
		return err
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	// QRESYNC and UIDONLY clients get a single VANISHED response (RFC 7162 /
	// RFC 9586) instead of per-message sequence-numbered EXPUNGE.
	if c.qresync || c.uidonly {
		if len(expungedUIDs) > 0 {
			var ids []string
			for _, u := range expungedUIDs {
				ids = append(ids, strconv.FormatUint(uint64(u), 10))
			}
			c.writef("* VANISHED %s", compressUIDList(ids))
		}
	} else {
		// Emit EXPUNGE responses high-to-low so sequence numbers stay valid.
		for i := len(expunged) - 1; i >= 0; i-- {
			c.writef("* %d EXPUNGE", expunged[i])
		}
	}
	c.ok(tag, "EXPUNGE completed")
}

// cmdCopy / cmdMove implement COPY and MOVE (and their UID variants) to another
// mailbox. COPY appends copies; MOVE also expunges the sources.
func (c *conn) cmdCopyMove(tag, args string, byUID, move bool) {
	if !c.requireAuth(tag) {
		return
	}
	if c.selected == nil {
		c.no(tag, "no mailbox selected")
		return
	}
	setStr, dstTok := cut(strings.TrimSpace(args), " ")
	dst := normalizeMailbox(unquote(strings.TrimSpace(dstTok)))

	var movedSeqs []uint32
	err := c.acc.Tx(c.ctx, func(tx store.Tx) error {
		src, err := tx.QueryMessage().FilterMailbox(c.selected.ID).SortUID().List()
		if err != nil {
			return err
		}
		dmb, err := c.acc.MailboxFind(tx, dst)
		if err != nil {
			return err
		}
		if dmb == nil {
			nmb, _, _, _, e := c.acc.MailboxCreate(tx, dst, store.SpecialUse{})
			if e != nil {
				return e
			}
			dmb = &nmb
		}
		var maxUID uint32
		if len(src) > 0 {
			maxUID = uint32(src[len(src)-1].UID)
		}
		var match func(uint32) bool
		if byUID {
			match = parseUIDSet(setStr, maxUID)
		} else {
			match = parseUIDSet(setStr, uint32(len(src)))
		}
		var chosen []store.Message
		for i, m := range src {
			sel := match(uint32(m.UID))
			if !byUID {
				sel = match(uint32(i + 1))
			}
			if sel {
				chosen = append(chosen, m)
				movedSeqs = append(movedSeqs, uint32(i+1))
			}
		}
		for _, m := range chosen {
			// Copy: read the body and append to the destination mailbox.
			body := c.acc.MessageReader(c.ctx, m)
			nm := &store.Message{Flags: m.Flags, Keywords: m.Keywords}
			if _, err := c.acc.MessageAdd(tx, dmb, nm, body, store.AddOpts{}); err != nil {
				return err
			}
		}
		if move && len(chosen) > 0 {
			if _, _, err := c.acc.MessageRemove(tx, 0, c.selected, store.RemoveOpts{Expunge: true}, chosen...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.no(tag, err.Error())
		return
	}
	if move {
		for i := len(movedSeqs) - 1; i >= 0; i-- {
			c.writef("* %d EXPUNGE", movedSeqs[i])
		}
		c.ok(tag, "MOVE completed")
		return
	}
	c.ok(tag, "COPY completed")
}

// readLiteral reads an IMAP literal given the trailing "{n}" or "{n+}" spec at
// the end of the current command line. For a synchronizing literal ({n}) it
// sends a "+ " continuation before reading.
func (c *conn) readLiteral(spec string) ([]byte, error) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "{") || !strings.HasSuffix(spec, "}") {
		return nil, errNo("missing literal")
	}
	inner := spec[1 : len(spec)-1]
	sync := true
	if strings.HasSuffix(inner, "+") {
		sync = false
		inner = strings.TrimSuffix(inner, "+")
	}
	n, err := strconv.Atoi(inner)
	if err != nil || n < 0 {
		return nil, errNo("bad literal size")
	}
	// Bound the bytes this command may RETAIN before allocating: not just this
	// literal against MaxSize, but the running per-command budget, so a
	// MULTIAPPEND/CATENATE can't accumulate N×MaxSize on one connection (APPENDLIMIT
	// / RFC 9051 [TOOBIG]). For a synchronizing literal we reject before sending the
	// "+" continuation so the oversized payload is never invited. For a non-sync
	// (LITERAL+) literal the bytes are already inbound, so we drain them in a
	// bounded loop to keep the command stream aligned, then reject.
	if !c.chargeBudget(int64(n)) {
		if !sync {
			c.discard(int64(n))
		}
		return nil, errNo("[TOOBIG] literal exceeds APPENDLIMIT")
	}
	if sync {
		c.writef("+ ready for literal")
		c.flush()
	}
	buf := make([]byte, n)
	for read := 0; read < n; {
		m, err := c.r.Read(buf[read:])
		if m > 0 {
			read += m
		}
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// discard drains and throws away up to n bytes from the connection using a fixed
// buffer, so an oversized non-synchronizing (LITERAL+) literal can be skipped
// without allocating n bytes. Best-effort: a read error just stops the drain
// (the caller is already returning an error / tearing down the command).
func (c *conn) discard(n int64) {
	_, _ = io.CopyN(io.Discard, c.r, n)
}

// chargeBudget debits n bytes from the current command's retained-memory budget,
// returning false (without debiting) if it would be exceeded. It bounds the TOTAL
// bytes a single command holds in RAM across all its literals and assembled parts
// — the per-literal cap alone doesn't stop a MULTIAPPEND or CATENATE from
// accumulating N×MaxSize. When no limit is configured (srv.MaxSize == 0,
// cmdLimited false) it always allows. cmdLimited is checked instead of
// "cmdBudget <= 0" so a budget legitimately decremented to exactly 0 is treated
// as exhausted (reject), not as the unlimited sentinel.
func (c *conn) chargeBudget(n int64) bool {
	if !c.cmdLimited { // no limit configured (MaxSize==0)
		return true
	}
	if n > c.cmdBudget {
		return false
	}
	c.cmdBudget -= n
	return true
}

// normalizeMailbox maps the IMAP "INBOX" special name to the kernel's "Inbox".
func normalizeMailbox(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "Inbox"
	}
	return name
}

// newBytesBlob wraps a byte slice as a store.BlobReader for APPEND.
func newBytesBlob(b []byte) store.BlobReader {
	return &bytesBlob{Reader: bytes.NewReader(b), size: int64(len(b))}
}

type bytesBlob struct {
	*bytes.Reader
	size int64
}

func (b *bytesBlob) Size() int64  { return b.size }
func (b *bytesBlob) Close() error { return nil }
