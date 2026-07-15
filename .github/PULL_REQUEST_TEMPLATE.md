<!--
Thanks for contributing to octo-mail! Fill out the sections below.
For substantial changes, link the issue where the approach was discussed first.
Delete sections that genuinely don't apply (write "N/A" rather than leaving blanks).
-->

## Description

**Summary**

<!-- One or two sentences describing the change. -->

**Why / Context**

<!-- Why is this change needed? What problem does it solve? Reference the issue below. -->

## Type of Change

<!-- Mark with an "x" all that apply. -->

- [ ] 🚀 **Feature** — new functionality
- [ ] 🐛 **Bug fix** — non-breaking fix for an issue
- [ ] ♻️ **Refactor** — code change that neither fixes a bug nor adds a feature
- [ ] 📝 **Docs** — documentation only
- [ ] ✅ **Test** — adding or updating tests
- [ ] 🔧 **Chore** — build, tooling, dependencies (incl. `go mod vendor` bumps)
- [ ] ⚡ **Performance** — performance improvement
- [ ] 🔁 **CI / Build** — CI configuration or scripts

## Related Issues

<!-- Keep traceability. GitHub auto-closes the issue when the PR is merged. -->
<!-- Use: Closes #123, Fixes #456, Relates to #789 -->

- Closes #

## Changes Made

<!-- Bullet the key changes. Focus on WHAT and WHY, not a line-by-line diff. -->

-
-
-

## Architectural / schema impact

<!--
Does this touch the change-log (storage/postgres/schema/02_changelog.sql ★), the
projection tables (03_projections.sql), tenant isolation (core/directory), or the
protocol → core → storage dependency direction? If so, explain why the ordering /
consistency / isolation guarantees still hold. Write "none" if not applicable.
-->

none

## Related Coding Spec

<!--
Which `.coding/spec/` guidelines govern this change, and does the diff follow them?
This keeps human reviewers and the coding-implement / coding-check sub-agents aligned
on the same conventions. List the specific files you relied on (not just the index),
or write "N/A" for changes with no applicable spec (e.g. pure CI tweaks).
-->

- [ ] Change follows the applicable spec files listed below
- [ ] Spec updated in this PR if the change establishes a new convention or invalidates an existing rule

**Applicable spec(s):**

<!-- e.g.
- `.coding/spec/backend/database-guidelines.md` — per-account advisory-lock write path
- `.coding/spec/backend/error-handling.md` — `fmt.Errorf("...: %w", err)` wrapping
- `.coding/spec/guides/cross-layer-thinking-guide.md`
-->

-

## Screenshots / Demo

<!-- REQUIRED for any webui / user-visible behavior change. Add before/after if applicable. -->
<!-- Drag & drop images, or paste a screen-recording link. If not applicable, write "N/A". -->

N/A

## Testing

<!-- How was this verified? Be specific so reviewers can reproduce. -->

- [ ] **Unit / package tests** added or updated
- [ ] **Integration / E2E tests** added or updated (`e2e/`, `storage/postgres/*_test.go`)
- [ ] **Manual verification** performed (steps below)

**How to verify locally**

```bash
# Tests need REAL infra: PostgreSQL 17 (OCTO_MAIL_DSN) + MinIO/S3.
# A green run with no DB means tests were SKIPPED, not passed.
make test   # go test -p 1 ./...  (MUST be -p 1: packages share one Postgres DB)
```

**Test cases covered**

-

## Self-Checklist

<!-- Confirm before requesting review. -->

- [ ] I have performed a self-review of my own code
- [ ] `make fmt` and `make vet` are clean
- [ ] `make test` passes locally against **real** PostgreSQL + MinIO (`-p 1`)
- [ ] Added or updated tests that prove the fix / feature works
- [ ] `protocol/*` packages depend on `core` interfaces only (not `storage/*`)
- [ ] Reused mox protocol algorithms rather than reimplementing them (no `replace` in `go.mod`)
- [ ] Edited `webui/assets/*.ts` (not `*.js`) and ran `make frontend` if the frontend changed
- [ ] Updated documentation where relevant (README / docs / `.coding/spec`)
- [ ] No stray debug logging, secrets, or credentials committed
- [ ] Commits are focused with clear messages; PR is a single concern
- [ ] No breaking changes (or they are called out below)

## Risk / Reviewer Notes

<!-- Help reviewers focus. What needs extra attention? What could break? -->

- **Areas needing careful review:**
-
- **Potential impact / side effects:**
-
- **Rollback plan:**
-

## Deployment / Migration Notes

<!-- Anything ops / release needs to know. Delete if not applicable. -->

- [ ] **Schema change** included (idempotent DDL in `storage/postgres/schema/NN_*.sql`)
- [ ] **Configuration / env vars** added or changed (`OCTO_MAIL_*`, documented + defaulted in `cmd/octo-mail/config.go`)
- [ ] **No deployment action** required
