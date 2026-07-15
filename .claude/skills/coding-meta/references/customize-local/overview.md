# Local Customization Overview

This directory is for local AI working in a user project where Coding was installed through npm and `coding init` has already been run. The AI should modify generated `.coding/` and platform directories inside the project, not Coding CLI upstream source code.

## First Determine What The User Actually Wants To Change

| User wording | Read first |
| --- | --- |
| "Change the Coding flow / phases / next prompt" | `change-workflow.md` |
| "Change task creation, status, archive, or hooks" | `change-task-lifecycle.md` |
| "AI did not read context / change injected content" | `change-context-loading.md` |
| "A platform hook is not behaving as expected" | `change-hooks.md` |
| "Change implement/check/research agent behavior" | `change-agents.md` |
| "Add a skill/command/workflow/prompt" | `change-skills-or-commands.md` |
| "Adjust the project spec structure" | `change-spec-structure.md` |
| "Add team conventions and local notes" | `add-project-local-conventions.md` |

## General Operation Order

1. **Confirm directories**: inspect the `.claude/` directory in the project.
2. **Confirm the current active task**: run `python3 ./.coding/scripts/task.py current --source`.
3. **Read the local source of truth**: prefer `.coding/workflow.md`, `.coding/config.yaml`, and relevant `.claude/` files.
4. **Modify narrowly**: edit only files related to the user's request.
5. **Synchronize semantics**: if a shared flow changes, check whether `.claude/` entry points also need changes; if a `.claude/` entry changes, check whether `.coding/workflow.md` still agrees.

## Local File Priority

| Layer | Files |
| --- | --- |
| Workflow | `.coding/workflow.md` |
| Project configuration | `.coding/config.yaml` |
| Task material | `.coding/tasks/<task>/` |
| Project specs | `.coding/spec/` |
| Runtime scripts | `.coding/scripts/` |
| Platform integration | `.claude/` |

## Things Not To Do By Default

- Do not edit the global npm install directory.
- Do not edit `node_modules/@limenglin/coding`.
- Do not assume the user has the Coding GitHub repository.
- Do not overwrite local files already modified by the user with default templates.
- Do not put team project rules into public `coding-meta`; project rules belong in `.coding/spec/` or a local skill.

## When To Inspect Upstream Source

Switch to an upstream source-code perspective only when the user explicitly expresses one of these goals:

- "I want to open a PR to Coding"
- "I want to change npm package publish contents"
- "I want to fork Coding"
- "I want to modify the generation logic for `coding init/update`"

Otherwise, default to modifying local Coding files inside the user project.
