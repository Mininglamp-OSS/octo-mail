# Hooks And Settings

Hooks/settings are the entry layer that connects Claude Code to Coding. They
decide which scripts Claude Code runs for which events.

## Settings Responsibilities

`.claude/settings.json` registers:

- session-start hook: injects a Coding overview when a new session starts or context resets.
- workflow-state hook: parses `[workflow-state:STATUS]` blocks from `.coding/workflow.md` and emits the body matching the current task `status` on each user input. Parser-only; the script does not embed fallback content.
- sub-agent context hook: injects task context when implementation/check/research agents start.

## Hook Script Types

| Script | Purpose |
| --- | --- |
| `session-start.py` | Generates session-start context. |
| `inject-workflow-state.py` | Parses `[workflow-state:STATUS]` blocks in `.coding/workflow.md` and emits the body matching the current task status. Falls back to `Refer to workflow.md for current step.` when no matching block exists. |
| `inject-subagent-context.py` | Injects PRD, JSONL context, and related spec/research into sub-agents. |

## Local Change Scenarios

| User need | Edit location |
| --- | --- |
| AI should see more/less context in a new session | `.claude/hooks/session-start.py`. |
| Per-turn hint policy should change | `[workflow-state:STATUS]` block in `.coding/workflow.md`. The hook parses workflow.md verbatim — no script edit required. |
| Sub-agent cannot read PRD/spec | `inject-subagent-context` hook or agent prelude. |
| Disable an automatic injection | The corresponding hook registration in `.claude/settings.json`. |

## Modification Principles

1. **Settings wire things up; hooks define behavior**. If only the hook changes, the platform may never call it. If only settings change, behavior may not change.
2. **Hooks read local `.coding/`, not upstream source**. `.coding/scripts/` and `.coding/workflow.md` in the user project are the default targets.
3. **Errors must be visible**. Hook failures should tell the user what was not injected instead of silently leaving the AI without context.

## Troubleshooting Path

If the user says "AI did not read Coding state":

1. Check whether `.claude/settings.json` registers the hook.
2. Check whether the hook file exists.
3. Manually run the `.coding/scripts/get_context.py` or `task.py current --source` command that the hook depends on.
4. Check whether active task state exists in `.coding/.runtime/sessions/`.
5. Check whether the platform shell passes session identity.
