# Change Local Hooks

Hooks are the automation layer that connects Claude Code to Coding. When the user wants to change "when context is injected," "how shell commands inherit a session," or "which files are read before an agent starts," hooks are usually the edit point.

## Read These Files First

1. `.claude/settings.json`
2. `.claude/hooks/`
3. `.coding/scripts/common/active_task.py`
4. `.coding/scripts/common/session_context.py`
5. `.coding/workflow.md`

## Common Hook Types

| Hook | Purpose |
| --- | --- |
| session-start | Injects a Coding overview when a session starts, clears, or compacts. |
| workflow-state | Injects a state hint on each user input. |
| sub-agent context | Injects PRD/spec/research before an agent starts. |
| shell session bridge | Lets `task.py` commands in shell see the same session identity. |

## Modification Steps

1. Find the hook registration in settings/config.
2. Confirm the registered script path exists.
3. Read the hook script and identify inputs, outputs, and called `.coding/scripts/`.
4. Modify hook behavior.
5. If the hook depends on workflow content, synchronize `.coding/workflow.md`.

## Example: Change New-Session Injection Content

First find the session-start hook:

```text
.claude/settings.json
.claude/hooks/session-start.py
```

If the hook ultimately calls `.coding/scripts/get_context.py` or `session_context.py`, editing the local script is usually more robust than hard-coding content in the hook.

## Example: Agent Did Not Read JSONL

First confirm:

```bash
python3 ./.coding/scripts/task.py current --source
python3 ./.coding/scripts/task.py validate <task>
```

If the task and JSONL are correct, edit the `inject-subagent-context` hook (hook push). If the agent file itself carries a read prelude, edit the agent file instead.

## Notes

- Settings handle registration, hook scripts handle behavior; inspect both together.
- Hooks should read project-local `.coding/`; they should not depend on Coding upstream source paths.
- Hook failures should produce visible errors so AI does not silently lose context.
