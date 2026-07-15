#!/usr/bin/env python3
"""Coding per-turn breadcrumb hook (Claude Code UserPromptSubmit).

Runs on every user prompt. Resolves the active task through Coding'
session-aware active task resolver and emits a short <workflow-state>
block reminding the main AI what task is active and its expected flow.

Breadcrumb text is pulled exclusively from workflow.md
[workflow-state:STATUS] tag blocks — workflow.md is the single source of
truth. There are no fallback dicts in this script: when workflow.md is
missing or a tag is absent, the breadcrumb degrades to a generic
"Refer to workflow.md for current step." line so users see (and fix)
the broken state instead of the hook silently masking it.

Written to Claude Code's hooks directory via writeSharedHooks() at init
time.

Silent exit 0 cases (no output):
  - No .coding/ directory found (not a Coding project)
  - task.json malformed or missing status
"""
from __future__ import annotations

import json
import os
import re
import sys
import queue
import threading
from pathlib import Path

# Force UTF-8 on stdin/stdout/stderr on Windows. Default codepage there is
# cp936 / cp1252 / etc. — non-ASCII content (Chinese task names, prd snippets)
# both in stdin (hook payload from host CLI) and stdout (our emitted blocks)
# raises UnicodeDecodeError / UnicodeEncodeError. Equivalent to `python -X utf8`
# but applied per-stream so we don't depend on host CLI's command wiring.
if sys.platform.startswith("win"):
    import io as _io
    for _stream_name in ("stdin", "stdout", "stderr"):
        _stream = getattr(sys, _stream_name, None)
        if _stream is None:
            continue
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except Exception:
                pass  # Optional Windows stream setup; keep hook startup non-fatal.
        elif hasattr(_stream, "detach"):
            try:
                setattr(sys, _stream_name, _io.TextIOWrapper(_stream.detach(), encoding="utf-8", errors="replace"))
            except Exception:
                pass  # Optional Windows stream setup; keep hook startup non-fatal.
from typing import Optional


# ---------------------------------------------------------------------------
# CWD-robust Coding root discovery (fixes hook-path-robustness for this hook)
# ---------------------------------------------------------------------------

def find_coding_root(start: Path) -> Optional[Path]:
    """Walk up from start to find directory containing .coding/.

    Handles CWD drift: subdirectory launches, monorepo packages, etc.
    Returns None if no .coding/ found (silent no-op).
    """
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / ".coding").is_dir():
            return cur
        cur = cur.parent
    return None


# ---------------------------------------------------------------------------
# Active task discovery
# ---------------------------------------------------------------------------

def _resolve_active_task(root: Path, input_data: dict):
    scripts_dir = root / ".coding" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from common.active_task import resolve_active_task  # type: ignore[import-not-found]

    return resolve_active_task(root, input_data, platform="claude")


def get_active_task(root: Path, input_data: dict) -> Optional[tuple[str, str, str]]:
    """Return (task_id, status, source) from the current active task."""
    active = _resolve_active_task(root, input_data)
    if not active.task_path:
        return None

    task_dir = Path(active.task_path)
    if not task_dir.is_absolute():
        task_dir = root / task_dir
    if active.stale:
        return task_dir.name, f"stale_{active.source_type}", active.source

    task_json = task_dir / "task.json"
    if not task_json.is_file():
        return None
    try:
        data = json.loads(task_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    task_id = data.get("id") or task_dir.name
    status = data.get("status", "")
    if not isinstance(status, str) or not status:
        return None
    return task_id, status, active.source


# ---------------------------------------------------------------------------
# Breadcrumb loading: parse workflow.md, fall back to hardcoded defaults
# ---------------------------------------------------------------------------

# Supports STATUS values with letters, digits, underscores, hyphens
# (so "in-review" / "blocked-by-team" work alongside "in_progress").
_TAG_RE = re.compile(
    r"\[workflow-state:([A-Za-z0-9_-]+)\]\s*\n(.*?)\n\s*\[/workflow-state:\1\]",
    re.DOTALL,
)

def load_breadcrumbs(root: Path) -> dict[str, str]:
    """Parse workflow.md for [workflow-state:STATUS] blocks.

    Returns {status: body_text}. workflow.md is the single source of
    truth — there are no fallback dicts in this script. Missing tags
    (or a missing/unreadable workflow.md) fall back to a generic line
    in build_breadcrumb so users see the broken state and fix
    workflow.md, rather than the hook silently masking the issue.
    """
    workflow = root / ".coding" / "workflow.md"
    if not workflow.is_file():
        return {}
    try:
        content = workflow.read_text(encoding="utf-8")
    except OSError:
        return {}

    result: dict[str, str] = {}
    for match in _TAG_RE.finditer(content):
        status = match.group(1)
        body = match.group(2).strip()
        if body:
            result[status] = body
    return result


def build_breadcrumb(
    task_id: Optional[str],
    status: str,
    templates: dict[str, str],
    source: str | None = None,
) -> str:
    """Build the <workflow-state>...</workflow-state> block.

    - Known status (tag present in workflow.md) → detailed template body
    - Unknown status (no tag, or workflow.md missing) → generic
      "Refer to workflow.md for current step." line
    - `no_task` pseudo-status (task_id is None) → header omits task info
    """
    body = templates.get(status)
    if body is None:
        body = "Refer to workflow.md for current step."
    header = f"Status: {status}" if task_id is None else f"Task: {task_id} ({status})"
    return f"<workflow-state>\n{header}\n{body}\n</workflow-state>"


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def _load_hook_input() -> dict:
    """Read hook JSON without trusting host runners to close stdin.

    Some hook runners can leave stdin open while sending no payload. A plain
    `json.load(sys.stdin)` then blocks forever. Normal hook runners write the
    complete JSON payload and close stdin, so the short daemon read preserves
    that path while failing closed to `{}` for non-piping hosts.
    """
    result_queue: "queue.Queue[str | Exception]" = queue.Queue(maxsize=1)

    def _read() -> None:
        try:
            result_queue.put(sys.stdin.read())
        except Exception as exc:
            result_queue.put(exc)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        raw = result_queue.get(timeout=0.2)
    except queue.Empty:
        return {}

    if isinstance(raw, Exception):
        return {}
    try:
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def main() -> int:
    if os.environ.get("CODING_HOOKS") == "0" or os.environ.get("CODING_DISABLE_HOOKS") == "1":
        return 0

    data = _load_hook_input()

    cwd_str = data.get("cwd") or os.getcwd()
    cwd = Path(cwd_str)

    root = find_coding_root(cwd)
    if root is None:
        return 0  # not a Coding project

    templates = load_breadcrumbs(root)
    task = get_active_task(root, data)
    if task is None:
        # No active task — still emit a breadcrumb nudging AI toward
        # coding-brainstorm + task.py create when user describes real work.
        breadcrumb = build_breadcrumb(None, "no_task", templates)
    else:
        task_id, status, source = task
        breadcrumb = build_breadcrumb(task_id, status, templates, source)

    output = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": breadcrumb,
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
