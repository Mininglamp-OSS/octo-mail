# Cross-Layer Thinking Guide

> **Purpose**: Think through data flow across layers before implementing.

---

## The Problem

**Most bugs happen at layer boundaries**, not within layers.

Common cross-layer bugs:

- API returns format A, frontend expects format B
- Database stores X, service transforms to Y, but loses data
- Multiple layers implement the same logic differently

---

## Before Implementing Cross-Layer Features

### Step 1: Map the Data Flow

Draw out how data moves:

```
Source → Transform → Store → Retrieve → Transform → Display
```

For each arrow, ask:

- What format is the data in?
- What could go wrong?
- Who is responsible for validation?

### Step 2: Identify Boundaries

| Boundary              | Common Issues                     |
| --------------------- | --------------------------------- |
| API ↔ Service         | Type mismatches, missing fields   |
| Service ↔ Database    | Format conversions, null handling |
| Backend ↔ Frontend    | Serialization, date formats       |
| Component ↔ Component | Props shape changes               |

### Step 3: Define Contracts

For each boundary:

- What is the exact input format?
- What is the exact output format?
- What errors can occur?

---

## Common Cross-Layer Mistakes

### Mistake 1: Implicit Format Assumptions

**Bad**: Assuming date format without checking

**Good**: Explicit format conversion at boundaries

### Mistake 2: Scattered Validation

**Bad**: Validating the same thing in multiple layers

**Good**: Validate once at the entry point

### Mistake 3: Leaky Abstractions

**Bad**: Component knows about database schema

**Good**: Each layer only knows its neighbors

### Mistake 4: Every Consumer Parses The Same Payload

**Bad**: A command reads JSONL records and casts fields inline:

```typescript
const status = (rec as { status?: string }).status;
const labels = (rec as { labels?: string[] }).labels;
```

This looks local, but it means every consumer owns a private version of the
record contract. The next field change will update one command and miss another.

**Good**: Decode once at the record boundary, then export typed projections:

```typescript
if (!isTaskRecord(rec)) return false;
return rec.status === filter.status;
```

**Rule**: For append-only logs, JSON streams, RPC payloads, or config files,
create one owner for:

- event / payload type definitions
- type guards and normalization from `unknown`
- metadata projections used by UI commands
- reducers that replay state from the source of truth

Rendering code may format fields, but it must not redefine the payload contract.

---

## Checklist for Cross-Layer Features

Before implementation:

- [ ] Mapped the complete data flow
- [ ] Identified all layer boundaries
- [ ] Defined format at each boundary
- [ ] Decided where validation happens

After implementation:

- [ ] Tested with edge cases (null, empty, invalid)
- [ ] Verified error handling at each boundary
- [ ] Checked data survives round-trip
- [ ] Checked that consumers import shared decoders / projections instead of
      casting payload fields locally
- [ ] Checked that derived state points back to the source event identifier
      (`seq`, `id`, `version`) instead of inventing a second cursor

---

## Command Template / Runtime Consistency

In Coding, command templates (e.g., `record-session.md`) are both documentation
and runtime input. Editing one is a cross-layer boundary: the file writer that
installs it and any runtime parser that reads it must agree.

### Checklist: After Modifying Any Command Template

- [ ] Find the command under `src/templates/claude/commands/coding/`
- [ ] Update the Markdown source
- [ ] Confirm no runtime parser expected the old wording
- [ ] Run `/coding:check-cross-layer` to verify nothing was missed

---

## Generated Runtime Template Upgrade Consistency

Some generated files are both documentation and runtime input. In Coding,
`.coding/workflow.md` is parsed by `get_context.py`, `workflow_phase.py`,
SessionStart filters, and per-turn hooks. Template changes must be validated
against both fresh init and upgrade paths.

### Checklist: After Modifying A Runtime-Parsed Template

- [ ] Identify every runtime parser that reads the template, not just the file
      writer that installs it
- [ ] Check whether relevant syntax lives outside obvious managed regions
      such as tag blocks
- [ ] Verify fresh `init` output and a versioned `update` scenario that writes
      the older `.coding/.version`
- [ ] Add an upgrade regression using an older pristine template fixture, then
      assert the installed file reaches the current packaged shape
- [ ] Update the backend spec that owns the runtime contract

---

## Versioned Documentation Boundary

Versioned documentation is a cross-layer boundary: source paths, `docs.json`
version routing, and the rendered version selector must all describe the same
release line.

### Checklist: Before Editing Versioned Docs

- [ ] Identify the target release line: stable, beta, or RC
- [ ] Verify the edited MDX path matches that line:
  - stable: `docs-site/{start,advanced,...}` and `docs-site/zh/{start,advanced,...}`
  - beta: `docs-site/beta/**` and `docs-site/zh/beta/**`
  - RC: `docs-site/rc/**` and `docs-site/zh/rc/**`
- [ ] Verify `docs.json` navigation points the version label to the same paths
- [ ] Grep the opposite tree for release-line-specific terms before committing
- [ ] Treat beta content appearing under root release paths as a source-path bug,
      not a rendering bug

**Real-world example**: A beta-only task workflow change documented
`prd.md` + `design.md` + `implement.md` and task-creation consent
under root `start/` and `advanced/` paths. The docs site then
served 0.6 beta behavior under the Release selector. The fix was to restore root
release docs, move the 0.6 content to `beta/` and `zh/beta/`, and add a grep
audit for beta markers against the root release tree.

**Real-world example**: A workflow-routing change updated the `[workflow-state:*]`
blocks in `.coding/workflow.md`. Fresh init was correct, but `coding update` only
merged those blocks and preserved stale routing text outside them. Result:
upgraded projects got new hook scripts but old workflow routing, so
`get_context.py --mode phase` could return empty Phase 2.1 detail.

---

## Mode-Detection Probe Checklist

When a CLI auto-detects a mode by probing a remote resource (e.g., checking if `index.json` exists to decide marketplace vs direct download):

### Before implementing:

- [ ] Probe runs in **ALL** code paths that use the result (interactive, `-y`, `--flag` combos)
- [ ] 404 vs transient error are distinguished — don't treat both as "not found"
- [ ] Transient errors **abort or retry**, never silently switch modes
- [ ] Shared state (caches, prefetched data) is **reset** when context changes (e.g., user switches source)
- [ ] **Shortcut paths** (e.g., `--template` skipping picker) must have the same error-handling quality as the probed path — check that downstream functions don't call catch-all wrappers

### After implementing:

- [ ] Trace every path from probe result to the mode-decision branch — no fallthrough
- [ ] External format contracts (giget URI, raw URLs) are tested or at least documented as comments
- [ ] Metadata reads consume a complete response or use a streaming parser — never parse a fixed-size prefix as full JSON
- [ ] When reconstructing a composite identifier from parsed parts, verify **all** fields are included and in the **correct position** (e.g., `provider:repo/path#ref` not `provider:repo#ref/path`)
- [ ] Verify that **action functions** called after a shortcut don't internally use the old catch-all fetch — they must use the probe-quality variant when error distinction matters

**Real-world example**: Custom registry flow had 8 bugs across 3 review rounds: (1) probe only ran in interactive mode, (2) transient errors fell through to wrong mode, (3) giget URI had `#ref` in wrong position, (4) prefetched templates leaked across source switches, (5) `--template` shortcut bypassed probe but `downloadTemplateById` internally used catch-all `fetchTemplateIndex`, turning timeouts into "Template not found".

**Real-world example**: Agent-session update hints fetched npm `latest` metadata with `response.read(4096)` and then parsed it as complete JSON. The `@limenglin/coding` package metadata exceeded 4 KB, so the JSON was truncated, parse failed silently, and the first session injection showed no update hint. Fix: read the complete response before parsing, and add a regression where `version` is followed by an 8 KB metadata tail.

---

## Command Template / Runtime Consistency

In Coding, command templates (e.g., `record-session.md`) are both documentation
and runtime input. Editing one is a cross-layer boundary: the file writer that
installs it and any runtime parser that reads it must agree.

### Checklist: After Modifying Any Command Template

- [ ] Find the command under `src/templates/claude/commands/coding/`
- [ ] Update the Markdown source
- [ ] Confirm no runtime parser expected the old wording
- [ ] Run `/coding:check-cross-layer` to verify nothing was missed

---

## Generated Runtime Template Upgrade Consistency

Some generated files are both documentation and runtime input. In Coding,
`.coding/workflow.md` is parsed by `get_context.py`, `workflow_phase.py`,
SessionStart filters, and per-turn hooks. Template changes must be validated
against both fresh init and upgrade paths.

### Checklist: After Modifying A Runtime-Parsed Template

- [ ] Identify every runtime parser that reads the template, not just the file
  writer that installs it
- [ ] Check whether relevant syntax lives outside obvious managed regions
  such as tag blocks
- [ ] Verify fresh `init` output and a versioned `update` scenario that writes
  the older `.coding/.version`
- [ ] Add an upgrade regression using an older pristine template fixture, then
  assert the installed file reaches the current packaged shape
- [ ] Update the backend spec that owns the runtime contract

**Real-world example**: A workflow-routing change updated the `[workflow-state:*]`
blocks in `.coding/workflow.md`. Fresh init was correct, but `coding update` only
merged those blocks and preserved stale routing text outside them. Result:
upgraded projects got new hook scripts but old workflow routing, so
`get_context.py --mode phase` could return empty Phase 2.1 detail.

---

## Mode-Detection Probe Checklist

When a CLI auto-detects a mode by probing a remote resource (e.g., checking if `index.json` exists to decide marketplace vs direct download):

### Before implementing:
- [ ] Probe runs in **ALL** code paths that use the result (interactive, `-y`, `--flag` combos)
- [ ] 404 vs transient error are distinguished — don't treat both as "not found"
- [ ] Transient errors **abort or retry**, never silently switch modes
- [ ] Shared state (caches, prefetched data) is **reset** when context changes (e.g., user switches source)
- [ ] **Shortcut paths** (e.g., `--template` skipping picker) must have the same error-handling quality as the probed path — check that downstream functions don't call catch-all wrappers

### After implementing:
- [ ] Trace every path from probe result to the mode-decision branch — no fallthrough
- [ ] External format contracts (giget URI, raw URLs) are tested or at least documented as comments
- [ ] Metadata reads consume a complete response or use a streaming parser — never parse a fixed-size prefix as full JSON
- [ ] When reconstructing a composite identifier from parsed parts, verify **all** fields are included and in the **correct position** (e.g., `provider:repo/path#ref` not `provider:repo#ref/path`)
- [ ] Verify that **action functions** called after a shortcut don't internally use the old catch-all fetch — they must use the probe-quality variant when error distinction matters

**Real-world example**: Custom registry flow had 8 bugs across 3 review rounds: (1) probe only ran in interactive mode, (2) transient errors fell through to wrong mode, (3) giget URI had `#ref` in wrong position, (4) prefetched templates leaked across source switches, (5) `--template` shortcut bypassed probe but `downloadTemplateById` internally used catch-all `fetchTemplateIndex`, turning timeouts into "Template not found".

**Real-world example**: Agent-session update hints fetched npm `latest` metadata with `response.read(4096)` and then parsed it as complete JSON. The `@limenglin/coding` package metadata exceeded 4 KB, so the JSON was truncated, parse failed silently, and the first session injection showed no update hint. Fix: read the complete response before parsing, and add a regression where `version` is followed by an 8 KB metadata tail.

---

## When to Create Flow Documentation

Create detailed flow docs when:

- Feature spans 3+ layers
- Multiple teams are involved
- Data format is complex
- Feature has caused bugs before

---

## Record Log / Projection Boundary

Append-only logs are cross-layer contracts. A single record travels through:

```
CLI input → record writer → tasks.jsonl → reader → filter → reducer → display
```

### Checklist: After Adding A New Record Kind Or Field

- [ ] Add the record kind to the central record taxonomy
- [ ] Add a typed record variant or type guard at the record layer
- [ ] Add normalization helpers for array/object fields that come from
      user input or JSON
- [ ] Keep `seq` / `id` assignment in the record writer only
- [ ] Make filters and reducers consume the typed record guard, not local casts
- [ ] Make display code consume reducer output or typed records, not raw JSON
- [ ] Add at least one regression that proves history replay and live filtering
      use the same filter model

**Real-world example**: A task log added `kind: "milestone"`, `description`,
`context`, labels, and `lastSeq`. The first implementation replayed state
correctly, but several commands still re-parsed record payload fields with
local casts. The fix was to make the core record layer own the typed record
variant and its type guard, and to make a single reducer the only projection
that replays derived state.
