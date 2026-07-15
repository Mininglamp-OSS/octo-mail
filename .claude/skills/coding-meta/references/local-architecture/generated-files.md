# Local Files Generated After Init

`coding init` writes the Coding runtime into the user project. Later, `coding update` tries to update Coding-managed template files, but it uses `.coding/.template-hashes.json` to determine which files have already been modified by the user.

This page only describes files that are visible and editable inside the user project.

## `.coding/`

```text
.coding/
├── workflow.md
├── config.yaml
├── .developer
├── .version
├── .template-hashes.json
├── .runtime/
├── scripts/
├── spec/
├── tasks/
└── workspace/
```

| Path | Usually editable? | Notes |
| --- | --- | --- |
| `.coding/workflow.md` | Yes | Local workflow documentation and AI routing rules. |
| `.coding/config.yaml` | Yes | Project configuration, hooks, packages, journal line limits, and related settings. |
| `.coding/spec/` | Yes | Project specs, intended to be updated regularly by users and AI. |
| `.coding/tasks/` | Yes | Task material and research artifacts, maintained by the task workflow. |
| `.coding/workspace/` | Yes | Session records, usually written by `add_session.py`. |
| `.coding/scripts/` | Carefully | Local runtime. It can be customized, but only after understanding the call chain. |
| `.coding/.runtime/` | No | Runtime state, usually written automatically by hooks/scripts. |
| `.coding/.developer` | Carefully | Current developer identity. |
| `.coding/.version` | No | Coding version record used by update/migration logic. |
| `.coding/.template-hashes.json` | No | Template hash record. Do not hand-write business rules here. |

## Platform Directory

Coding targets Claude Code, so all platform files live under `.claude/`:

| Category | Paths | Purpose |
| --- | --- | --- |
| hooks | `.claude/hooks/` | Inject session context, workflow-state, and sub-agent context. |
| settings | `.claude/settings.json` | Tell the platform when to run hooks. |
| agents | `.claude/agents/` | Define agents such as `coding-research`, `coding-implement`, and `coding-check`. |
| skills | `.claude/skills/` | Skills that auto-trigger or can be read by AI. |
| commands | `.claude/commands/` | Explicit user-invoked command entry points. |

When modifying the `.claude/` directory, also confirm whether `.coding/workflow.md` still describes the same flow.

## Meaning Of Template Hashes

`.coding/.template-hashes.json` records the content hash from the last time Coding wrote a template file. `coding update` uses it to distinguish three cases:

| Case | Update behavior |
| --- | --- |
| File was not modified by the user | It can be updated automatically. |
| File was modified by the user | Prompt the user to overwrite, keep, or generate `.new`. |
| File is no longer a current template | It may be deleted, renamed, or preserved according to migration rules. |

When an AI customizes local Coding files, it does not need to maintain hashes manually. It is normal for Coding update to recognize the result as "modified by the user."

## Local Customization Boundaries

Editable by default:

- `.coding/workflow.md`
- `.coding/config.yaml`
- `.coding/spec/**`
- `.coding/scripts/**`
- `.claude/` hooks, settings, agents, skills, and commands

Do not edit by default:

- Global npm install directory
- `node_modules/@limenglin/coding`
- Coding GitHub repository source code
- Concrete state files under `.coding/.runtime/**`
- Hash contents inside `.coding/.template-hashes.json`

Switch to the Coding CLI source-code perspective only when the user explicitly wants to contribute upstream.
