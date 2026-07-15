#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sub-Agent Context Injection Hook (Claude Code)

Injects task-specific context when sub-agents (implement, check, research) are spawned.

Core Design Philosophy:
- Hook is responsible for injecting all context, subagent works autonomously with complete info
- Each agent has a dedicated jsonl file defining its context
- No resume needed, no segmentation, behavior controlled by code not prompt

Trigger: PreToolUse (before Task tool call)

Context Source: Coding active task resolver points to task directory
- implement.jsonl - Implement agent dedicated context
- check.jsonl     - Check agent dedicated context
- prd.md          - Requirements document
- design.md       - Technical design for complex tasks
- implement.md    - Execution plan for complex tasks
"""
from __future__ import annotations

# IMPORTANT: Suppress all warnings FIRST
import warnings
warnings.filterwarnings("ignore")

import json
import os
import sys
from pathlib import Path
from typing import Any

# IMPORTANT: Force stdout to use UTF-8 on Windows
# This fixes UnicodeEncodeError when outputting non-ASCII characters
if sys.platform.startswith("win"):
    import io as _io
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    elif hasattr(sys.stdout, "detach"):
        sys.stdout = _io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8", errors="replace")  # type: ignore[union-attr]


# =============================================================================
# Path Constants (change here to rename directories)
# =============================================================================

DIR_WORKFLOW = ".coding"
DIR_SPEC = "spec"
FILE_TASK_JSON = "task.json"

# =============================================================================
# Subagent Constants (change here to rename subagent types)
# =============================================================================

AGENT_IMPLEMENT = "coding-implement"
AGENT_CHECK = "coding-check"
AGENT_RESEARCH = "coding-research"

# Agents that require a task directory
AGENTS_REQUIRE_TASK = (AGENT_IMPLEMENT, AGENT_CHECK)
# All supported agents
AGENTS_ALL = (AGENT_IMPLEMENT, AGENT_CHECK, AGENT_RESEARCH)


def find_repo_root(start_path: str) -> str | None:
    """
    Find git repo root from start_path upwards

    Returns:
        Repo root path, or None if not found
    """
    current = Path(start_path).resolve()
    while current != current.parent:
        if (current / ".git").exists():
            return str(current)
        current = current.parent
    return None


def get_current_task(repo_root: str, input_data: dict) -> str | None:
    """Resolve current task directory through the unified active task resolver."""
    scripts_dir = Path(repo_root) / DIR_WORKFLOW / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from common.active_task import resolve_active_task  # type: ignore[import-not-found]
    except Exception:
        return None

    active = resolve_active_task(
        Path(repo_root),
        input_data,
        platform="claude",
    )
    return active.task_path


def _check_status_is_pass(repo_root: str, task_dir: str) -> bool:
    """Return True when the task's loop check_status is "pass".

    Reads <repo_root>/<task_dir>/task.json and inspects
    meta.loop.check_status. Any missing file / parse error / absent field
    fails toward False (regular check), so a missing spike is safe.
    """
    try:
        task_json = Path(repo_root) / task_dir / FILE_TASK_JSON
        data = json.loads(task_json.read_text(encoding="utf-8"))
        return data.get("meta", {}).get("loop", {}).get("check_status") == "pass"
    except Exception:
        return False


def read_file_content(base_path: str, file_path: str) -> str | None:
    """Read file content, return None if file doesn't exist"""
    full_path = os.path.join(base_path, file_path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None
    return None


def read_directory_contents(
    base_path: str, dir_path: str, max_files: int = 20
) -> list[tuple[str, str]]:
    """
    Read all .md files in a directory

    Args:
        base_path: Base path (usually repo_root)
        dir_path: Directory relative path
        max_files: Max files to read (prevent huge directories)

    Returns:
        [(file_path, content), ...]
    """
    full_path = os.path.join(base_path, dir_path)
    if not os.path.exists(full_path) or not os.path.isdir(full_path):
        return []

    results = []
    try:
        # Only read .md files, sorted by filename
        md_files = sorted(
            [
                f
                for f in os.listdir(full_path)
                if f.endswith(".md") and os.path.isfile(os.path.join(full_path, f))
            ]
        )

        for filename in md_files[:max_files]:
            file_full_path = os.path.join(full_path, filename)
            relative_path = os.path.join(dir_path, filename)
            try:
                with open(file_full_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    results.append((relative_path, content))
            except Exception:
                continue
    except Exception:
        pass

    return results


def read_jsonl_entries(base_path: str, jsonl_path: str) -> list[tuple[str, str]]:
    """
    Read all file/directory contents referenced in jsonl file

    Schema:
        {"file": "path/to/file.md", "reason": "..."}
        {"file": "path/to/dir/", "type": "directory", "reason": "..."}
        {"_example": "..."}          # seed row — skipped (no `file` field)

    Rows without a ``file`` field (e.g. the self-describing seed line written
    by ``task.py create`` before the agent has curated entries) are skipped
    silently. If the resulting entry list is empty, a stderr warning is
    emitted so the operator can debug missing context.

    Returns:
        [(path, content), ...]
    """
    full_path = os.path.join(base_path, jsonl_path)
    if not os.path.exists(full_path):
        print(
            f"[inject-subagent-context] WARN: {jsonl_path} not found — "
            f"sub-agent will receive only task artifacts",
            file=sys.stderr,
        )
        return []

    results = []
    saw_real_entry = False
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    file_path = item.get("file") or item.get("path")
                    entry_type = item.get("type", "file")

                    if not file_path:
                        # Seed / comment row — skip silently
                        continue

                    saw_real_entry = True
                    if entry_type == "directory":
                        # Read all .md files in directory
                        dir_contents = read_directory_contents(base_path, file_path)
                        results.extend(dir_contents)
                    else:
                        # Read single file
                        content = read_file_content(base_path, file_path)
                        if content:
                            results.append((file_path, content))
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    if not saw_real_entry:
        print(
            f"[inject-subagent-context] WARN: {jsonl_path} has no curated "
            f"entries (only seed / empty) — sub-agent will receive only "
            f"task artifacts. See workflow.md planning artifact guidance.",
            file=sys.stderr,
        )

    return results




def get_agent_context(repo_root: str, task_dir: str, agent_type: str) -> str:
    """
    Get context from {agent_type}.jsonl for the specified agent.
    Only reads implement.jsonl or check.jsonl (the two JSONL files the task system creates).
    """
    context_parts = []

    agent_jsonl = f"{task_dir}/{agent_type}.jsonl"
    for file_path, content in read_jsonl_entries(repo_root, agent_jsonl):
        context_parts.append(f"=== {file_path} ===\n{content}")

    return "\n\n".join(context_parts)


def get_implement_context(repo_root: str, task_dir: str) -> str:
    """
    Complete context for Implement Agent

    Read order:
    1. All files in implement.jsonl (spec/research manifests)
    2. prd.md (requirements)
    3. design.md if present (technical design)
    4. implement.md if present (execution plan)
    """
    context_parts = []

    # 1. Read implement.jsonl
    base_context = get_agent_context(repo_root, task_dir, "implement")
    if base_context:
        context_parts.append(base_context)

    # 2. Requirements document
    prd_content = read_file_content(repo_root, f"{task_dir}/prd.md")
    if prd_content:
        context_parts.append(f"=== {task_dir}/prd.md (Requirements) ===\n{prd_content}")

    # 3. Technical design for complex tasks
    design_content = read_file_content(repo_root, f"{task_dir}/design.md")
    if design_content:
        context_parts.append(
            f"=== {task_dir}/design.md (Technical Design) ===\n{design_content}"
        )

    # 4. Execution plan for complex tasks
    implement_plan_content = read_file_content(repo_root, f"{task_dir}/implement.md")
    if implement_plan_content:
        context_parts.append(
            f"=== {task_dir}/implement.md (Execution Plan) ===\n{implement_plan_content}"
        )

    return "\n\n".join(context_parts)


def get_check_context(repo_root: str, task_dir: str) -> str:
    """
    Context for Check Agent: check.jsonl + task artifacts.
    """
    context_parts = []

    for file_path, content in read_jsonl_entries(repo_root, f"{task_dir}/check.jsonl"):
        context_parts.append(f"=== {file_path} ===\n{content}")

    prd_content = read_file_content(repo_root, f"{task_dir}/prd.md")
    if prd_content:
        context_parts.append(f"=== {task_dir}/prd.md (Requirements) ===\n{prd_content}")

    design_content = read_file_content(repo_root, f"{task_dir}/design.md")
    if design_content:
        context_parts.append(
            f"=== {task_dir}/design.md (Technical Design) ===\n{design_content}"
        )

    implement_plan_content = read_file_content(repo_root, f"{task_dir}/implement.md")
    if implement_plan_content:
        context_parts.append(
            f"=== {task_dir}/implement.md (Execution Plan) ===\n{implement_plan_content}"
        )

    return "\n\n".join(context_parts)


def get_finish_context(repo_root: str, task_dir: str) -> str:
    """
    Context for Finish phase: reuses check.jsonl + prd.md
    (Finish is a final check, same context source.)
    """
    return get_check_context(repo_root, task_dir)



def build_implement_prompt(original_prompt: str, context: str) -> str:
    """Build complete prompt for Implement"""
    return f"""<!-- coding-hook-injected -->
# Implement Agent Task

You are the Implement Agent in the Multi-Agent Pipeline.

## Your Context

All the information you need has been prepared for you:

{context}

---

## Your Task

{original_prompt}

---

## Workflow

1. **Understand specs** - All dev specs are injected above, understand them
    2. **Understand task artifacts** - Read requirements, technical design if present, and execution plan if present
    3. **Implement feature** - Implement following specs and task artifacts
4. **Self-check** - Ensure code quality against check specs

## Important Constraints

- Do NOT execute git commit, only code modifications
- Follow all dev specs injected above
- Report list of modified/created files when done"""


def build_check_prompt(original_prompt: str, context: str) -> str:
    """Build complete prompt for Check"""
    return f"""<!-- coding-hook-injected -->
# Check Agent Task

You are the Check Agent in the Multi-Agent Pipeline (code and cross-layer checker).

## Your Context

All check specs and dev specs you need:

{context}

---

## Your Task

{original_prompt}

---

## Workflow

1. **Get changes** - Run `git diff --name-only` and `git diff` to get code changes
2. **Check against specs** - Check item by item against specs above
3. **Self-fix** - Fix issues directly, don't just report
4. **Run verification** - Run project's lint, typecheck, and project tests

## Important Constraints

- Fix issues yourself, don't just report
- Must execute complete checklist in check specs
- Pay special attention to impact radius analysis (L1-L5)"""


def build_finish_prompt(original_prompt: str, context: str) -> str:
    """Build complete prompt for Finish (final check before PR)"""
    return f"""<!-- coding-hook-injected -->
# Finish Agent Task

You are performing the final check before creating a PR.

## Your Context

Finish checklist and requirements:

{context}

---

## Your Task

{original_prompt}

---

## Workflow

1. **Review changes** - Run `git diff --name-only` to see all changed files
	2. **Verify task artifacts** - Check requirements in prd.md and, when present, design.md / implement.md
3. **Spec sync** - Analyze whether changes introduce new patterns, contracts, or conventions
   - If new pattern/convention found: read target spec file → update it → update index.md if needed
   - If infra/cross-layer change: follow the 7-section mandatory template from update-spec.md
   - If pure code fix with no new patterns: skip this step
4. **Run final checks** - Execute lint, typecheck, and project tests
5. **Verify acceptance criteria** - For each acceptance criterion in prd.md, run
   it if it is executable (a command / test / grep with expected output) and
   render a table `| AC | check | result |`; mark non-executable criteria "manual"
6. **Confirm ready** - Ensure code is ready for PR

## Important Constraints

- You MAY update spec files when gaps are detected (use update-spec.md as guide)
- MUST read the target spec file BEFORE editing (avoid duplicating existing content)
- Do NOT update specs for trivial changes (typos, formatting, obvious fixes)
- If critical CODE issues found, report them clearly (fix specs, not code)
- Verify all acceptance criteria in prd.md are met
- Verify design.md and implement.md constraints when those files are present"""



def get_research_context(repo_root: str, task_dir: str | None) -> str:
    """
    Context for Research Agent — project structure overview for spec directories.

    `task_dir` kept for signature parity with get_implement_context / get_check_context
    so the dispatcher can call them uniformly.
    """
    _ = task_dir
    context_parts = []

    # 1. Project structure overview (dynamically discover spec directories)
    spec_path = f"{DIR_WORKFLOW}/{DIR_SPEC}"
    spec_root = Path(repo_root) / DIR_WORKFLOW / DIR_SPEC

    # Build spec tree dynamically
    tree_lines = [f"{spec_path}/"]
    if spec_root.is_dir():
        pkg_dirs = sorted(d for d in spec_root.iterdir() if d.is_dir())
        for i, pkg_dir in enumerate(pkg_dirs):
            is_last = i == len(pkg_dirs) - 1
            prefix = "└── " if is_last else "├── "
            layers = sorted(d.name for d in pkg_dir.iterdir() if d.is_dir())
            layer_info = f" ({', '.join(layers)})" if layers else ""
            tree_lines.append(f"{prefix}{pkg_dir.name}/{layer_info}")

    spec_tree = "\n".join(tree_lines)

    project_structure = f"""## Project Spec Directory Structure

```
{spec_tree}
```

To get structured package info, run: `python3 ./{DIR_WORKFLOW}/scripts/get_context.py --mode packages`

## Search Tips

- Spec files: `{spec_path}/**/*.md`
- Code search: Use Glob and Grep tools
- Tech solutions: Use a web-search MCP tool if one is configured in your environment"""

    context_parts.append(project_structure)

    return "\n\n".join(context_parts)


def build_research_prompt(original_prompt: str, context: str) -> str:
    """Build complete prompt for Research"""
    return f"""# Research Agent Task

You are the Research Agent in the Multi-Agent Pipeline (search researcher).

## Core Principle

**You do one thing: find and explain information.**

You are a documenter, not a reviewer.

## Project Info

{context}

---

## Your Task

{original_prompt}

---

## Workflow

1. **Understand query** - Determine search type (internal/external) and scope
2. **Plan search** - List search steps for complex queries
3. **Execute search** - Execute multiple independent searches in parallel
4. **Organize results** - Output structured report

## Search Tools

| Tool | Purpose |
|------|---------|
| Glob | Search by filename pattern |
| Grep | Search by content |
| Read | Read file content |
| (web-search MCP, if configured) | External web / code search |

## Strict Boundaries

**Only allowed**: Describe what exists, where it is, how it works

**Forbidden** (unless explicitly asked):
- Suggest improvements
- Criticize implementation
- Recommend refactoring
- Modify any files

## Report Format

Provide structured search results including:
- List of files found (with paths)
- Code pattern analysis (if applicable)
- Related spec documents
- External references (if any)"""


def _string_value(value: Any) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped
    return ""


def _extract_subagent_type(tool_input: dict) -> str:
    for key in ("subagent_type", "subagentType", "name"):
        agent_name = _string_value(tool_input.get(key))
        if agent_name:
            return agent_name
    return ""


def _parse_hook_input(input_data: dict) -> tuple[str, str, dict]:
    """Parse Claude Code hook input.

    Returns (subagent_type, original_prompt, tool_input). Claude Code passes
    ``tool_name=Task`` with ``tool_input.subagent_type`` (plus ``prompt``).
    """
    tool_input = input_data.get("tool_input", {})

    tool_name = input_data.get("tool_name", "")
    if tool_name.lower() in ("task", "agent"):
        return (
            _extract_subagent_type(tool_input),
            tool_input.get("prompt", ""),
            tool_input,
        )

    return "", "", tool_input


def _warn_and_allow(message: str) -> None:
    """Surface a warning to the model WITHOUT blocking the dispatch, then exit 0.

    In Claude Code a PreToolUse hook's stderr is only fed to the model on exit 2
    (which blocks the tool). To make a message visible on exit 0 we use
    hookSpecificOutput.additionalContext. We pair it with permissionDecision
    "allow" (docs-confirmed) rather than context-only (uncertain); this
    affirmatively approves the Task dispatch, which is acceptable for sub-agents.
    """
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "coding: dispatching sub-agent without injected task context",
        "additionalContext": message,
    }}))
    sys.exit(0)


def main():
    if os.environ.get("CODING_HOOKS") == "0" or os.environ.get("CODING_DISABLE_HOOKS") == "1":
        sys.exit(0)

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    subagent_type, original_prompt, tool_input = _parse_hook_input(input_data)
    cwd = input_data.get("cwd", os.getcwd())

    # Only handle subagent types we care about
    if subagent_type not in AGENTS_ALL:
        sys.exit(0)

    # Find repo root
    repo_root = find_repo_root(cwd)
    if not repo_root:
        sys.exit(0)

    # Get current task directory (research doesn't require it)
    task_dir = get_current_task(repo_root, input_data)

    # implement/check need task directory
    if subagent_type in AGENTS_REQUIRE_TASK:
        if not task_dir:
            # Probe decision: use allow+additionalContext (safer; docs-confirmed).
            _warn_and_allow(
                f"coding: no active task resolved for `{subagent_type}` — running "
                "WITHOUT injected prd/spec. Read the `Active task:` first line of "
                "your prompt and load that task's jsonl + prd/design/implement "
                "yourself. If unexpected, check for multiple open windows "
                "(multi-session active-task resolution is skipped for safety)."
            )
        # Check if task directory exists
        task_dir_full = os.path.join(repo_root, task_dir)
        if not os.path.exists(task_dir_full):
            _warn_and_allow(
                f"coding: active task path `{task_dir}` does not exist — running "
                "WITHOUT injected context; the pointer may be stale (run "
                "`task.py finish` or re-`start`)."
            )

    # Check for [finish] marker in prompt (check agent with finish context)
    is_finish_phase = "[finish]" in original_prompt.lower()
    # Belt-and-suspenders: once the loop is green (check_status=pass), the next
    # check dispatch IS the final pass, so load finish context even without the
    # explicit marker. The [finish] marker remains an explicit override.
    if not is_finish_phase and subagent_type == AGENT_CHECK and task_dir:
        is_finish_phase = _check_status_is_pass(repo_root, task_dir)

    # Get context and build prompt based on subagent type
    if subagent_type == AGENT_IMPLEMENT:
        assert task_dir is not None  # validated above
        context = get_implement_context(repo_root, task_dir)
        new_prompt = build_implement_prompt(original_prompt, context)
    elif subagent_type == AGENT_CHECK:
        assert task_dir is not None  # validated above
        if is_finish_phase:
            # Finish phase: use finish context (lighter, focused on final verification)
            context = get_finish_context(repo_root, task_dir)
            new_prompt = build_finish_prompt(original_prompt, context)
        else:
            # Regular check phase: use check context (full specs for self-fix loop)
            context = get_check_context(repo_root, task_dir)
            new_prompt = build_check_prompt(original_prompt, context)
    elif subagent_type == AGENT_RESEARCH:
        # Research can work without task directory
        context = get_research_context(repo_root, task_dir)
        new_prompt = build_research_prompt(original_prompt, context)
    else:
        sys.exit(0)

    if not context:
        sys.exit(0)

    # Return updated input with the injected prompt (Claude Code PreToolUse).
    updated = {**tool_input, "prompt": new_prompt}
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated,
        },
    }

    print(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
