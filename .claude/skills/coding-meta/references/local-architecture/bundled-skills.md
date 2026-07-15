# Bundled Skills

"Bundled skills" are multi-file built-in skills shipped inside the Coding CLI npm package. Unlike marketplace skills (which a user installs separately into their own `.claude/skills/`), bundled skills are written automatically into the Claude Code skill root by `coding init` and kept in sync by `coding update`. They are part of Coding itself, not third-party content.

A bundled skill is a directory under `packages/cli/src/templates/common/bundled-skills/<skill>/` that already contains its own `SKILL.md` (with YAML frontmatter) plus optional `references/`, assets, or other supporting files. Coding copies the whole directory tree as-is into the skill root, so references stay lazy-loadable instead of being flattened into one oversized `SKILL.md`.

## What Counts As Bundled (vs. Adjacent Concepts)

| Source path | Type | How it ships |
| --- | --- | --- |
| `templates/common/bundled-skills/<name>/` | Bundled skill (multi-file) | Whole directory copied to the skill root |
| `templates/common/skills/<name>.md` | Single-file workflow skill | Wrapped with frontmatter, written as `<root>/<name>/SKILL.md` |
| `templates/common/commands/<name>.md` | Slash command | Written to `.claude/commands/coding/` |
| User skills under `.claude/skills/<my-skill>/` | Marketplace or user-authored | Not managed by Coding at all |

The Coding CLI never touches anything that is not produced by one of its own template loaders. Anything a user drops into the skill root by hand is left alone.

## Current Bundled Skills (v0.6.0)

The set is discovered at runtime by listing directories under `templates/common/bundled-skills/`:

| Skill | Purpose |
| --- | --- |
| `coding-meta` | This skill. Explains the local Coding architecture and customization entry points to an AI working inside a user project. |
| `coding-session-insight` | Wraps the `coding mem` CLI so an AI knows when and how to reach into past Claude Code conversation logs. |
| `coding-spec-bootstrap` | Workflow for creating or refreshing `.coding/spec/` from the real codebase (with optional GitNexus / ABCoder integration). |

The list is discovered at runtime, so adding a new directory under `bundled-skills/` is the only step required to register a new skill (see "Adding a New Bundled Skill" below).

## Where Bundled Skills Land

The Claude Code configurator calls `writeSkills(<root>, <workflowSkills>, resolveBundledSkills(ctx))` during `coding init`. `resolveBundledSkills` reads every directory under `templates/common/bundled-skills/`, resolves placeholders, and returns a flat list of `{relativePath, content}` entries. `writeSkills` then mirrors them under the skill root.

| Platform | Bundled skill root | Notes |
| --- | --- | --- |
| Claude Code | `.claude/skills/<skill>/` | `configureClaude` |

Two paths exercise the same data:

1. `configureClaude(cwd)` writes files during `coding init`.
2. `collectPlatformTemplates("claude-code")` (in `configurators/index.ts`) returns a `Map<filePath, content>` that `coding update` uses to detect drift and to populate `.coding/.template-hashes.json`. Both must produce byte-identical output, so they both call `resolveBundledSkills(ctx)` and `collectSkillTemplates(root, …, resolveBundledSkills(ctx))`.

## Dispatch Wiring (Code Path)

The mechanism that auto-dispatches bundled skills to platform skill roots lives in two files:

1. `packages/cli/src/templates/common/index.ts`
   - `listDirectories("bundled-skills")` enumerates the on-disk skills.
   - `listBundledSkillFiles(skillDir)` walks each skill's directory recursively and returns `{relativePath, content}` for every file.
   - `getBundledSkillTemplates()` returns the cached `CommonBundledSkill[]`.

2. `packages/cli/src/configurators/shared.ts`
   - `resolveBundledSkills(ctx)` flattens that list into `ResolvedSkillFile[]` with `<skill>/<relativePath>` paths and resolved placeholders.
   - `writeSkills(skillsRoot, workflowSkills, bundledSkills)` writes both workflow skills and bundled skill files under `skillsRoot`.
   - `collectSkillTemplates(skillsRoot, workflowSkills, bundledSkills)` returns the same shape as a `Map<filePath, content>` for the update / hash pipeline.

Every platform configurator that supports skills imports both helpers (see `claude.ts`). The `index.ts` `PLATFORM_FUNCTIONS` registry also calls `resolveBundledSkills(ctx)` inside each `collectTemplates` closure so `coding update` tracking stays consistent.

## Adding a New Bundled Skill

The shape and dispatch wiring are already generic, so adding a skill requires only file changes plus distribution verification.

1. **Create the directory tree.**

   ```
   packages/cli/src/templates/common/bundled-skills/<my-skill>/
     SKILL.md                     # YAML frontmatter + body
     references/                  # optional
       <topic>.md
     assets/                      # optional (anything readable as utf-8)
   ```

2. **Write a valid `SKILL.md` header.** The frontmatter must include at minimum:

   ```yaml
   ---
   name: <my-skill>
   description: "When the AI should reach for this skill. Triggering phrases go here."
   ---
   ```

   The `description` is what the auto-trigger mechanism matches against, so it should describe the user-intent triggers, not the skill's internals.

3. **Use placeholders where appropriate.** Bundled skill content runs through `resolvePlaceholders(file.content, ctx)`. Any `{{platform_name}}`, `{{python_cmd}}`, etc. token supported by `resolvePlaceholders` will be substituted.

4. **No dispatch wiring is required.** `listDirectories("bundled-skills")` discovers the new directory automatically, so it is received on the next `coding init` or `coding update`.

5. **Verify the distribution path** before shipping. Skipping any of these steps has historically caused features to be documented as bundled while the published npm tarball was missing the files:

   - Source files exist on the branch being tagged.
   - `pnpm --filter @limenglin/coding build` copies the asset into `dist/templates/common/bundled-skills/<skill>/`.
   - `npm pack --dry-run --json` includes the expected `dist/**` paths.
   - In a fresh temp project, `coding init` writes `.claude/skills/<skill>/SKILL.md`.
   - `.coding/.template-hashes.json` lists the generated files.
   - `coding update --dry-run` in that temp project reports "Already up to date!".

6. **Add a migration manifest entry** if the skill is added in a release that other projects will upgrade into. Without an explicit manifest entry the file will land via the standard "missing file" branch of `coding update`, but a manifest makes the change visible in the changelog.

## Overriding a Bundled Skill Locally

There is no formal "project-local skill" mechanism (e.g. `.coding/skills/`). Bundled skills are rooted under `.claude/skills/`, so any override is too.

The supported pattern relies on the existing template-hash diff in `coding update`:

1. Edit the local file directly. Example: `.claude/skills/coding-meta/SKILL.md`.
2. The file's hash now diverges from the entry in `.coding/.template-hashes.json`.
3. The next `coding update` detects the user modification and leaves the file untouched (Coding never overwrites user-modified files without an explicit `--force`).

Caveats:

- A future `coding update --force` will overwrite local edits. Keep the override under version control so it can be reapplied if needed.
- Marketplace skills installed under `.claude/skills/` with a different folder name (e.g. `.claude/skills/my-custom-meta/`) are untouched by Coding and are the cleaner option when the goal is to add behavior, not to mutate the bundled skill.
- Team-private conventions belong in `.coding/spec/` or in a separate marketplace-style local skill, not in modifications to `coding-meta` itself. See `customize-local/add-project-local-conventions.md`.

## Removing a Bundled Skill From a Project

There is no per-project opt-out flag for bundled skills. Two options:

1. **Delete the directory in the skill root.** `coding update` will see the file missing, compare against `.template-hashes.json`, and treat the deletion the same as any other user modification — it will not silently re-create the directory unless `--force` is passed.

2. **Pin a Coding version that did not ship the skill.** The bundled-skill set is determined at build time, so installing an older release of the CLI is the only way to permanently exclude a skill that the current release ships.

A third option — globally disabling all bundled skills — is not supported. The dispatch is unconditional in the configurator. Adding such a flag would require changing `PLATFORM_FUNCTIONS` in `configurators/index.ts` and the `configureClaude` function.

## Operating Rules

- Treat `templates/common/bundled-skills/` as the single source of truth for what bundled skills exist.
- Do not couple bundled skills to a specific CLI binary (e.g. `coding mem`) without surfacing the dependency in the skill's description and references — users on older releases may not have the command.
- Do not store project-private content in a bundled skill. Bundled skills are public, shipped to every user; project rules belong in `.coding/spec/` or a local skill.
