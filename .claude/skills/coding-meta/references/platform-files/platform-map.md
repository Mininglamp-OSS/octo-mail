# Platform File Map

This page lists the Coding file locations in a user project. Coding targets
Claude Code only, so all platform files live under `.claude/`.

## Layout

| Item | CLI flag | Directory |
| --- | --- | --- |
| Main directory | `--claude` (default) | `.claude/` |
| Skills | | `.claude/skills/` |
| Agents | | `.claude/agents/` |
| Hooks | | `.claude/hooks/` |
| Settings | | `.claude/settings.json` |
| Commands | | `.claude/commands/` |

## Coding Sub-Agents

Claude Code has `coding-research`, `coding-implement`, and `coding-check` agent
files under `.claude/agents/`. When changing implementation/check/research
behavior, look at those agent files first.

## Decision Rules When Modifying Platform Files

1. Modify files under `.claude/` unless shared workflow/spec files must also change.
2. User wants project rules: prefer `.coding/spec/` or a project-local skill.
3. User wants Coding behavior: edit `.coding/workflow.md` plus `.claude/` hooks/agents/skills/commands.

## When Paths Differ

User projects may already be customized. If this layout disagrees with local
files, use the actual settings/config in the user project as authoritative:

- Check the hook that `.claude/settings.json` registers.
- Check the script that a command points to.
- Judge behavior by the read rules currently written in the agent file.

Do not delete a custom file just because it is not listed in this path table.
