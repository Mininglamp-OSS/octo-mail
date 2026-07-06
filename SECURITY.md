# Security Policy

The octo-mail maintainers take security seriously. As a mail server kernel that
handles authentication, message content, and multi-tenant isolation, octo-mail
is security-sensitive by nature, and we appreciate the work of security
researchers in keeping it safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, report them privately through GitHub's coordinated disclosure workflow:

- Open a private advisory at
  **https://github.com/Mininglamp-OSS/octo-mail/security/advisories/new**

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The affected component or surface (IMAP / JMAP / SMTP / REST WebAPI / admin /
  storage / tenant isolation).
- Step-by-step reproduction instructions or a proof of concept.
- The version, commit SHA, and relevant configuration.
- Any suggested remediation, if you have one.

We are especially interested in reports concerning:

- **Cross-tenant isolation** — any path where one account or tenant can read or
  affect another's data.
- **Authentication and authorization** — SASL/SCRAM, account API keys
  (`omk_…`), the admin token, and session handling.
- **Message-handling** — parsing, MIME, header injection, or delivery paths that
  could be abused.
- **Remote code execution, SSRF, or injection** in any surface.

## What to expect

- We will acknowledge your report within a few business days.
- We will investigate and keep you informed of our progress.
- Once a fix is available, we will coordinate a disclosure timeline with you and
  credit you in the advisory unless you prefer to remain anonymous.

Please give us a reasonable opportunity to address the issue before any public
disclosure.

## Supported versions

octo-mail is under active development. Security fixes are applied to the `main`
branch; until tagged releases are published, please base security testing and
fixes on the latest `main`.

## Scope

This policy covers the octo-mail codebase in this repository. Vulnerabilities in
vendored third-party dependencies (under `vendor/`) should be reported to their
respective upstream projects; if a dependency issue affects octo-mail, we still
want to hear about it so we can update the pinned version.
