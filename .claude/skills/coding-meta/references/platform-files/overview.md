# Platform Files Overview

Coding targets Claude Code only. `.coding/` stores the shared runtime; `.claude/`
stores the adapter files that define how Claude Code enters Coding.

When a local AI modifies Coding, it should distinguish two file categories first:

- **Shared files**: `.coding/workflow.md`, `.coding/tasks/`, `.coding/spec/`, `.coding/scripts/`.
- **Platform files**: everything under `.claude/` (settings, hooks, agents, skills, commands).

Platform files do not store business state. They let Claude Code read Coding
state, call Coding scripts, and load Coding skills/agents/hooks.

## Platform File Categories

| Category | Paths | Purpose |
| --- | --- | --- |
| settings/config | `.claude/settings.json` | Register hooks and platform behavior. |
| hooks | `.claude/hooks/` | Inject context at session start, user input, agent startup, and shell execution. |
| agents | `.claude/agents/` | Define `coding-research`, `coding-implement`, and `coding-check`. |
| skills | `.claude/skills/` | Capability descriptions that auto-trigger or can be read on demand. |
| commands | `.claude/commands/` | Entry points explicitly invoked by the user. |

## How Claude Code Integrates

Claude Code is hook-driven: it triggers scripts on specific events and actively
injects Coding context into the AI.

Common capabilities:

- session-start injection of a `.coding/` overview.
- workflow-state hints for each user turn.
- PRD/spec/research injection when sub-agents start.
- Shell commands inheriting session identity.

To change "when the AI knows what," inspect `.claude/hooks/` and
`.claude/settings.json` first.

## Local Modification Order

When the user asks to customize behavior, the AI should inspect files in this order:

1. Read `.coding/workflow.md` to confirm the shared flow.
2. Read `.claude/settings.json` to see which hooks/agents/skills/commands are registered.
3. Read the target `.claude/` agents/skills/commands/hooks.
4. Modify the local file closest to the user's need.
5. If the change affects the shared flow, synchronize `.coding/workflow.md` or `.coding/spec/`.

Do not modify only platform files and forget the shared workflow. Do not modify
only `.coding/workflow.md` and forget that `.claude/` entry points may still
contain old descriptions.
