# Add Project-Local Conventions

Often the user does not need to change Coding mechanics; they need local AI to understand their team's conventions. In that case, prefer `.coding/spec/` or a project-local skill instead of editing `coding-meta`.

## Where To Put Things

| Content type | Location |
| --- | --- |
| Rules code must follow | `.coding/spec/<layer>/` |
| Cross-layer thinking methods | `.coding/spec/guides/` |
| AI capability for a project-specific flow | Platform-local skill |
| One-off task material | `.coding/tasks/<task>/` |
| Session summary | `.coding/workspace/<developer>/journal-N.md` |

## Create A Project-Local Skill

If the user wants AI to know "how this project customizes Coding," create a local skill:

```text
.claude/skills/coding-local/
└── SKILL.md
```

Example:

```md
---
name: coding-local
description: "Project-local Coding customizations for this repository. Use when changing this project's Coding workflow, hooks, local agents, or team-specific conventions."
---

# Coding Local

## Local Scope

This skill documents this repository's Coding customizations only.

## Custom Workflow Rules

- ...

## Local Hook Changes

- ...

## Local Agent Changes

- ...
```

For multi-platform projects, place equivalent versions in other platform skill directories, or use `.agents/skills/` for platforms that support the shared layer.

## Write To `.coding/spec/`

If the content is a coding convention, write it to spec. Examples:

```text
.coding/spec/backend/error-handling.md
.coding/spec/frontend/components.md
.coding/spec/guides/cross-platform-thinking-guide.md
```

After writing it, update the corresponding `index.md` so AI can find the new rule from the entry point.

## Make The Current Task Use New Conventions

After writing a spec, add it to the current task context:

```bash
python3 ./.coding/scripts/task.py add-context <task> implement ".coding/spec/backend/error-handling.md" "Error handling conventions"
python3 ./.coding/scripts/task.py add-context <task> check ".coding/spec/backend/error-handling.md" "Review error handling"
```

## Do Not Store Project-Private Rules In `coding-meta`

`coding-meta` is a public skill for understanding Coding architecture and local customization entry points. Put project-private content in:

- `.coding/spec/`
- a project-local skill
- the current task
- workspace journal

This prevents future updates to Coding's built-in `coding-meta` from overwriting the team's own conventions.
