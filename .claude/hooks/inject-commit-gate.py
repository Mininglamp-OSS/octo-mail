#!/usr/bin/env python3
"""Coding commit gate hook (Claude Code PreToolUse, matcher "Bash").

Denies `git commit` while the active task is `in_progress` and its latest
check did not pass (`meta.loop.check_status != "pass"`). This enforces the
loop-engineering rule "don't commit before check passes" as a hard gate.

Fail-OPEN by design: any ambiguity (no .coding/, no active task, parse error,
unusual command) results in ALLOW. A false deny is worse than a missed catch.

Deny contract (verified against Claude Code 2.1.210):
  - print deny JSON to stdout, exit 0. JSON is honored ONLY on exit 0.
  - to allow / not interfere: silent exit 0 with NO stdout.

Written to Claude Code's hooks directory via writeSharedHooks() at init time.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Force UTF-8 on stdin/stdout/stderr on Windows. Default codepage there is
# cp936 / cp1252 / etc. — non-ASCII content in stdin (hook payload) and stdout
# (our emitted deny reason) raises UnicodeDecodeError / UnicodeEncodeError.
# Equivalent to `python -X utf8` but applied per-stream so we don't depend on
# host CLI's command wiring.
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


# Conservative token-boundary match for common `git commit` forms:
#   git commit / git commit -m ... / git -C path commit / git --no-pager commit
# Does NOT parse && chains or strip quotes. Commit-shaped → deny path;
# everything else → allow. Documented false-positive: literal
# `echo "git commit"` may deny (acceptable; CODING_HOOKS=0 escapes).
_GIT_COMMIT_RE = re.compile(r"\bgit\b(?:\s+-C\s+\S+|\s+--?\S+)*\s+commit\b")


def looks_like_git_commit(cmd: str) -> bool:
    return _GIT_COMMIT_RE.search(cmd) is not None


def find_coding_root(start: Path) -> Optional[Path]:
    """Walk up from start to find directory containing .coding/.

    Handles CWD drift: subdirectory launches, monorepo packages, etc.
    Returns None if no .coding/ found (silent allow).
    """
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / ".coding").is_dir():
            return cur
        cur = cur.parent
    return None


def _resolve_active_task(root: Path, input_data: dict):
    scripts_dir = root / ".coding" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from common.active_task import resolve_active_task  # type: ignore[import-not-found]

    return resolve_active_task(root, input_data, platform="claude")


def _read_task_json(root: Path, active) -> Optional[dict]:
    task_dir = Path(active.task_path)
    if not task_dir.is_absolute():
        task_dir = root / task_dir
    task_json = task_dir / "task.json"
    if not task_json.is_file():
        return None
    try:
        data = json.loads(task_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


_DENY_REASON = (
    "Coding: the active in_progress task has not passed check. "
    "Run Phase 2.2 (coding-check) until `task.py set-check pass`, "
    "or override with CODING_HOOKS=0."
)


def _emit_deny() -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": _DENY_REASON,
        }
    }
    print(json.dumps(output))


def main() -> int:
    if os.environ.get("CODING_HOOKS") == "0" or os.environ.get("CODING_DISABLE_HOOKS") == "1":
        return 0

    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw and raw.strip() else {}
    except (json.JSONDecodeError, ValueError, OSError):
        return 0
    if not isinstance(data, dict):
        return 0

    if data.get("tool_name") != "Bash":
        return 0

    tool_input = data.get("tool_input")
    cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(cmd, str):
        return 0

    if not looks_like_git_commit(cmd):
        return 0

    cwd_str = data.get("cwd") or os.getcwd()
    root = find_coding_root(Path(cwd_str))
    if root is None:
        return 0  # not a Coding project → allow

    try:
        active = _resolve_active_task(root, data)
    except Exception:
        return 0  # fail-open on any resolver error

    if not active.task_path or active.stale:
        return 0  # no active task → allow

    task_data = _read_task_json(root, active)
    if task_data is None:
        return 0

    if task_data.get("status") != "in_progress":
        return 0  # completed/planning never gated

    meta = task_data.get("meta")
    loop = meta.get("loop") if isinstance(meta, dict) else None
    check_status = loop.get("check_status", "unknown") if isinstance(loop, dict) else "unknown"
    if check_status == "pass":
        return 0

    _emit_deny()
    return 0


if __name__ == "__main__":
    sys.exit(main())
