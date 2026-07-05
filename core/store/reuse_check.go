package store

// Compile-time proof that the pure protocol packages are reusable as a module
// dependency (the reuse boundary that the whole rewrite rests on). These imports
// are lifted verbatim; if they compile here they compile in the protocol layer.
import (
	_ "github.com/mjl-/mox/dkim"
	_ "github.com/mjl-/mox/dmarc"
	_ "github.com/mjl-/mox/dns"
	_ "github.com/mjl-/mox/dsn"
	_ "github.com/mjl-/mox/message"
	_ "github.com/mjl-/mox/smtp"
	_ "github.com/mjl-/mox/spf"
)
