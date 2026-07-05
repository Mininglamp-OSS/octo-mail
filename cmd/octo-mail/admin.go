package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/ops/mailboxops"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

// cmdPasswd sets a principal's password: octo-mail passwd <login> <password>.
// Provisioning helper so operators can create credentials without a separate
// tool. Uses the same argon2id+SCRAM hashing the auth path verifies against.
func cmdPasswd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: octo-mail passwd <login> <password>")
	}
	login, password := args[0], args[1]
	ctx := context.Background()
	cfg := loadConfig()

	bs, err := blob.NewFS(cfg.blobDir)
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.NewDirectory().SetPassword(ctx, login, password); err != nil {
		return err
	}
	fmt.Printf("password set for %s\n", login)
	return nil
}

// cmdGenDKIM generates a per-tenant DKIM key and prints the TXT record to
// publish: octo-mail gendkim <tenantID> <domain> <selector>.
func cmdGenDKIM(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: octo-mail gendkim <tenantID> <domain> <selector>")
	}
	var tenantID int64
	if _, err := fmt.Sscan(args[0], &tenantID); err != nil {
		return fmt.Errorf("bad tenantID: %w", err)
	}
	domain, selector := args[1], args[2]
	ctx := context.Background()
	cfg := loadConfig()

	s, err := postgres.Open(ctx, cfg.dsn, nil)
	if err != nil {
		return err
	}
	defer s.Close()

	var cipher *deliverability.KeyCipher
	if secret := os.Getenv("OCTO_MAIL_KEY_SECRET"); secret != "" {
		cipher, err = deliverability.NewKeyCipher([]byte(secret))
		if err != nil {
			return err
		}
	}
	txt, err := deliverability.GenerateTenantKeyEnc(ctx, s.Pool, cipher, tenantID, domain, selector)
	if err != nil {
		return err
	}
	fmt.Printf("publish this TXT record at %s._domainkey.%s:\n%s\n", selector, domain, txt)
	return nil
}

// cmdExport writes a mailbox to an mbox file:
// octo-mail export <tenant> <account> <mailbox> <out.mbox>
func cmdExport(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: octo-mail export <tenant> <account> <mailbox> <out.mbox>")
	}
	ctx := context.Background()
	cfg := loadConfig()
	bs, err := blob.NewFS(cfg.blobDir)
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()
	acc, err := s.OpenAccountForOps(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	f, err := os.Create(args[3])
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := mailboxops.ExportMbox(ctx, acc, args[2], f)
	if err != nil {
		return err
	}
	fmt.Printf("exported %d messages from %s/%s/%s to %s\n", n, args[0], args[1], args[2], args[3])
	return nil
}

// cmdImport reads an mbox file into a mailbox:
// octo-mail import <tenant> <account> <mailbox> <in.mbox>
func cmdImport(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: octo-mail import <tenant> <account> <mailbox> <in.mbox>")
	}
	ctx := context.Background()
	cfg := loadConfig()
	bs, err := blob.NewFS(cfg.blobDir)
	if err != nil {
		return err
	}
	s, err := postgres.Open(ctx, cfg.dsn, bs)
	if err != nil {
		return err
	}
	defer s.Close()
	acc, err := s.OpenAccountForOps(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	f, err := os.Open(args[3])
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := mailboxops.ImportMbox(ctx, acc, args[2], f)
	if err != nil {
		return err
	}
	fmt.Printf("imported %d messages into %s/%s/%s\n", n, args[0], args[1], args[2])
	return nil
}
