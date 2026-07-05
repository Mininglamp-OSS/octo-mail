package store

// Comm is a per-account subscription to the change stream, consumed by IMAP IDLE
// and JMAP push. On a single node it is fed in-process; on multiple nodes the
// coordinator (Postgres LISTEN/NOTIFY) wakes each node, which replays the log
// (seq > last) and re-synthesizes the []Change the protocol code expects.
//
// This mirrors the store.Comm contract so the protocol notify handlers bind
// unchanged; the transport underneath becomes durable and cross-node.
type Comm struct {
	Changes chan []Change

	accountID int64
	unreg     func()
}

// Account returns the account this Comm is bound to.
func (c *Comm) Account() int64 { return c.accountID }

// Close unregisters the subscription.
func (c *Comm) Close() {
	if c.unreg != nil {
		c.unreg()
		c.unreg = nil
	}
}

// NewComm constructs a Comm. Backends wire accountID and the unregister hook.
func NewComm(accountID int64, buf int, unreg func()) *Comm {
	return &Comm{
		Changes:   make(chan []Change, buf),
		accountID: accountID,
		unreg:     unreg,
	}
}
