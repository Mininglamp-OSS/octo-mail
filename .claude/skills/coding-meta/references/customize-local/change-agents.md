# Change Local Agents

When the user wants to change `coding-research`, `coding-implement`, or `coding-check` behavior, edit the agent files in the user project.

## Read These Files First

1. `.claude/agents/`
2. `.coding/workflow.md` Phase 2 / research routing
3. Current task `prd.md`
4. Current task `implement.jsonl` / `check.jsonl`
5. Relevant hook or agent prelude

## Path

| Item | Path |
| --- | --- |
| Claude Code | `.claude/agents/coding-*.md` |

Use the actual paths in the user project as authoritative.

## Common Needs

| Need | Which agent to edit |
| --- | --- |
| Research must write files, not only reply in chat | `coding-research` |
| Certain local specs must be read before implementation | `coding-implement` + `implement.jsonl` configuration rules |
| Specific commands must run during checking | `coding-check` |
| Agent must not modify certain directories | The corresponding agent's write boundary instructions |
| Agent output format must be fixed | The corresponding agent's final/reporting instructions |

## Modification Principles

1. **Preserve role boundaries**: research investigates and persists; implement writes implementation; check reviews and fixes.
2. **Do not hard-code project specs into agents**: long-term specs belong in `.coding/spec/`; agents are responsible for reading them.
3. **Make read order explicit**: active task -> PRD -> info -> JSONL -> spec/research.
4. **Make write boundaries explicit**: which directories may be written and which may not.

## Context Loading

Claude Code injects context via a hook before the agent starts. The agent file
should still retain responsibility boundaries — do not remove PRD/spec
requirements from the agent just because a hook injects context. If an agent
file contains a prelude for "read task/context after startup," do not remove
those steps when editing.
