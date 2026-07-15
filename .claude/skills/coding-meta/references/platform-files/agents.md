# Agents

Coding agent files define specialized roles. The Coding agents in a user project are:

- `coding-research`
- `coding-implement`
- `coding-check`

Agent files live under `.claude/agents/coding-*.md`, but responsibility
boundaries should stay consistent regardless of file location.

## Agent Responsibilities

| Agent | Responsibility |
| --- | --- |
| `coding-research` | Investigate the question and write findings into the current task's `research/`. |
| `coding-implement` | Implement against `prd.md`, optional `design.md` / `implement.md`, `implement.jsonl`, and related spec/research. |
| `coding-check` | Review changes, fix discovered issues, and run necessary checks. |

Agent files should not become generic chat prompts. They should define input
sources, write boundaries, whether code may be changed, and how results are reported.

## Path

| Item | Agent path |
| --- | --- |
| Claude Code | `.claude/agents/coding-*.md` |

## Context Loading

Claude Code uses hook push: the platform hook injects task context before the
agent starts, so the agent file can focus on responsibilities and boundaries.

If an agent needs to read context itself (agent pull), it reads:

- `python3 ./.coding/scripts/task.py current --source`
- `implement.jsonl` or `check.jsonl`
- spec/research files referenced by JSONL
- current task `prd.md`
- `design.md` if present
- `implement.md` if present

## Local Change Scenarios

| User need | Edit location |
| --- | --- |
| Implement agent must follow extra restrictions | `.claude/agents/coding-implement.md`. |
| Check agent must run project-specific commands | `coding-check` agent file, and `.coding/spec/` if needed. |
| Research agent must output a fixed format | `coding-research` agent file. |
| Agent cannot read task context | Agent prelude or `inject-subagent-context` hook. |
| Add a project-specific agent | `.claude/agents/` + related workflow/command/skill entry point. |

## Modification Principles

1. **Keep responsibilities single-purpose**. Do not mix research, implement, and check responsibilities into one agent.
2. **Specify the read order**. Agents must know to start from the active task, read jsonl/spec context, then read `prd.md`, `design.md` if present, and `implement.md` if present.
3. **Specify write boundaries**. Research usually only writes `research/`; implement can write code; check can fix issues.

## Do Not Default To Editing Upstream Templates

Local AI should default to modifying agent files inside the user project. Discuss
upstream template source only when the user explicitly wants to contribute the
change back to Coding.
