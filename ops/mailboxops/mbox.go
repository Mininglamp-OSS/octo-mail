// Package mailboxops provides operator backup/restore in mbox format (mboxrd):
// export all messages of a mailbox to an mbox stream, and import an mbox stream
// into a mailbox. This is the octo-mail equivalent of the export/import commands,
// operating through the kernel (blob-backed bodies, changelog delivery).
package mailboxops

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// mboxFrom is the mbox message separator line prefix.
const mboxFrom = "From "

// ExportMbox writes all non-expunged messages of a mailbox to w in mboxrd
// format. Lines beginning with "From " (and ">*From ") in the body are escaped
// by prepending ">". Returns the number of messages exported.
func ExportMbox(ctx context.Context, acc store.Account, mailbox string, w io.Writer) (int, error) {
	var msgs []store.Message
	err := acc.Tx(ctx, func(tx store.Tx) error {
		mb, err := acc.MailboxFind(tx, mailbox)
		if err != nil {
			return err
		}
		if mb == nil {
			return fmt.Errorf("no such mailbox %q", mailbox)
		}
		msgs, err = tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		return err
	})
	if err != nil {
		return 0, err
	}
	bw := bufio.NewWriter(w)
	n := 0
	for _, m := range msgs {
		r := acc.MessageReader(m)
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return n, err
		}
		// Separator line. A real address/date is not essential for round-trip.
		if _, err := fmt.Fprintf(bw, "From octo-mail@localhost\r\n"); err != nil {
			return n, err
		}
		if err := writeMboxrdBody(bw, data); err != nil {
			return n, err
		}
		// Blank line between messages.
		if _, err := bw.WriteString("\r\n"); err != nil {
			return n, err
		}
		n++
	}
	return n, bw.Flush()
}

// writeMboxrdBody writes body with mboxrd ">From " escaping.
func writeMboxrdBody(w *bufio.Writer, body []byte) error {
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Escape lines that are ">*From ".
		trimmed := strings.TrimLeft(line, ">")
		if strings.HasPrefix(trimmed, mboxFrom) {
			line = ">" + line
		}
		if _, err := w.WriteString(line + "\r\n"); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ImportMbox reads an mboxrd stream and delivers each message into the mailbox.
// Returns the number of messages imported. Unescapes ">*From " lines.
func ImportMbox(ctx context.Context, acc store.Account, mailbox string, r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var cur []string
	n := 0
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		raw := strings.Join(cur, "\r\n")
		cur = nil
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		_, err := acc.DeliverMailbox(mailbox, &store.Message{}, memBlob(raw+"\r\n"))
		if err != nil {
			return err
		}
		n++
		return nil
	}

	started := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, mboxFrom) {
			// New message boundary.
			if started {
				if err := flush(); err != nil {
					return n, err
				}
			}
			started = true
			continue
		}
		// Unescape ">*From ".
		if strings.HasPrefix(line, ">") {
			trimmed := strings.TrimLeft(line, ">")
			if strings.HasPrefix(trimmed, mboxFrom) {
				line = line[1:]
			}
		}
		cur = append(cur, line)
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if err := flush(); err != nil {
		return n, err
	}
	return n, nil
}

// memBlob adapts a string to store.BlobReader.
func memBlob(s string) store.BlobReader { return &mb{data: []byte(s)} }

type mb struct {
	data []byte
	off  int64
}

func (m *mb) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}
func (m *mb) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *mb) Size() int64  { return int64(len(m.data)) }
func (m *mb) Close() error { return nil }
