# Change Local Skills And Commands

When the user wants to change AI entry points, auto-trigger rules, or explicit command behavior, edit skills or commands in the `.claude/` directory.

Before editing, classify the skill you are about to touch:

- **Bundled upstream skill** — `coding-meta`, `coding-spec-bootstrap`, `coding-session-insight`. Source of truth lives in the Coding CLI repo under `packages/cli/src/templates/common/bundled-skills/<name>/`; auto-dispatched to the platform's skill root by `getBundledSkillTemplates()` on `coding init` / `coding update`. Local edits here are tracked by `.coding/.template-hashes.json` and will be flagged on the next update.
- **Project-local skill** — anything else under `.claude/skills/`. Owned by the user; not refreshed by `coding update`.

The remainder of this file uses "skill" for the local file; the override and conflict rules differ between the two cases.

## Read These Files First

1. `.coding/workflow.md`
2. `.claude/skills/` and `.claude/commands/`
3. Related agent or hook files
4. Whether project rules already exist in `.coding/spec/`
5. `.coding/.template-hashes.json` — confirms whether the skill you are about to edit is upstream-owned (entry present) or project-local (entry absent)

## Which Entry Type To Choose

| Goal | Recommendation |
| --- | --- |
| AI should automatically know a capability | Add or modify a skill. |
| User wants to trigger manually with a command | Add or modify a command. |
| Team project conventions | Prefer `.coding/spec/` or a project-local skill — never a bundled skill directory. |
| Tweak a bundled skill (`coding-meta` et al.) for the user's own project | Create a project-local sibling skill (different name) that overrides intent, or edit `.coding/spec/`. Edits inside the bundled skill directory survive only until the next `coding update` and will need a "keep" choice each time. |
| Contribute the change back upstream | Edit `packages/cli/src/templates/common/bundled-skills/<name>/` in the Coding CLI repo, not the deployed copy. |
| Change Coding flow semantics | Synchronize `.coding/workflow.md`. |

## Modify A Skill

A skill is usually:

```text
<skill-name>/
├── SKILL.md
└── references/
```

`SKILL.md` should be short and responsible for triggering/routing. Put long content in `references/` so AI can read it on demand.

The frontmatter description should specify when to use the skill. Example:

```yaml
description: "Use when customizing this project's deployment workflow and release checklist."
```

Do not write vague descriptions such as "helpful project skill"; they can trigger incorrectly.

### Bundled vs. Project-Local

The same directory shape is used by two very different ownership models:

| Aspect | Bundled (`coding-meta`, `coding-spec-bootstrap`, `coding-session-insight`) | Project-local |
| --- | --- | --- |
| Source of truth | `packages/cli/src/templates/common/bundled-skills/<name>/` in Coding CLI repo | Inside the user project itself |
| Dispatch | Auto-dispatched to the platform skill root by `getBundledSkillTemplates()` (`packages/cli/src/templates/common/index.ts`) on `coding init` / `coding update` | Created by the user (or another skill) and never moved |
| Hash tracking | Every file recorded in `.coding/.template-hashes.json`; conflict prompt on update | Not tracked |
| Editing locally | Allowed but will be marked "modified by user" on next update | Free editing |
| The right way to customize | Add a *new* project-local skill with a *different* name that supplements (or supersedes) the bundled one | Edit the file directly |

If the goal is "make my project's AI behave differently when discussing release notes," the answer is almost always a project-local skill, not surgery on `coding-meta/`.

## Modify A Command

Explicit entry points should state:

- How the user triggers it.
- Which `.coding/` files to read.
- Which scripts to run.
- How to report after completion.

If a command only repeats workflow rules, prefer making it reference/read `.coding/workflow.md` instead of maintaining a second copy of the flow.

## Paths

| Item | Path |
| --- | --- |
| Skills | `.claude/skills/` |
| Commands | `.claude/commands/` |

Both directories are deploy targets for the bundled skills. They receive a full
copy on `coding init` and refresh on `coding update`; nothing has to be wired by hand.

## Add A Project-Local Skill

If the user wants to document team-private customizations, create a project-local skill — never put project-private content into a bundled skill directory, since `coding update` will overwrite it.

```text
.claude/skills/project-coding-local/
└── SKILL.md
```

Pick a name that does **not** collide with the bundled set:

- `coding-meta`
- `coding-spec-bootstrap`
- `coding-session-insight`

A reused name causes `getBundledSkillTemplates()` to overwrite the project-local copy on the next update. A common convention is to prefix the project name: `acme-coding-deploy`, `acme-coding-onboarding`.

## Notes

- Do not change only part of an entry point while leaving stale descriptions elsewhere.
- Do not hide long-term engineering conventions inside a command; write them to `.coding/spec/`.
- Do not hand-edit files inside `coding-meta/`, `coding-spec-bootstrap/`, or `coding-session-insight/` under `.claude/skills/` expecting the change to persist — they are bundled and refreshed by `coding update`. Either contribute upstream or add a project-local skill that complements them.
- After `coding update` reports a "modified by you" conflict on a bundled skill file, choose **keep** only if you accept maintaining the divergence by hand; otherwise accept the overwrite and re-apply the intent as a project-local skill.
