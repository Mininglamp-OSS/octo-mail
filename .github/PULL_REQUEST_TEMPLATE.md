<!--
Thanks for contributing to octo-mail! Please fill out the sections below.
For substantial changes, link the issue where the approach was discussed.
-->

## Summary

<!-- What does this PR change, and why? -->

## Related issue

<!-- e.g. Closes #123. For non-trivial changes, an issue should exist first. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal cleanup
- [ ] Documentation
- [ ] Tests / CI

## Implementation notes

<!-- Anything reviewers should know: design decisions, trade-offs, follow-ups. -->

## Architectural / schema impact

<!--
Does this touch the change-log (schema/02_changelog.sql), projection tables,
tenant isolation, or the protocol → core → storage dependency direction?
If so, explain why the ordering/consistency/isolation guarantees still hold.
Write "none" if not applicable.
-->

## Checklist

- [ ] `make fmt` and `make vet` are clean
- [ ] `make test` passes locally (real PostgreSQL + MinIO, `-p 1`)
- [ ] Added or updated tests for the change
- [ ] `protocol/*` packages depend on `core` interfaces only (not `storage/*`)
- [ ] Updated documentation where relevant (README / docs / spec)
- [ ] Commits are focused with clear messages
