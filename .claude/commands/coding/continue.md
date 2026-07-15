# Continue Current Task

Resume work on the current task — pick up at the right phase/step in `.coding/workflow.md`.

---

## Step 1: Load Current Context

```bash
python3 ./.coding/scripts/get_context.py
```

Confirms: current task, git state, recent commits.

## Step 2: Load the Phase Index

```bash
python3 ./.coding/scripts/get_context.py --mode phase
```

Shows the Phase Index (Plan / Execute / Finish) with routing + skill mapping.

## Step 3: Decide Where You Are

`get_context.py` shows the active task's `status` field. Route by `status` + artifact presence. This command replaces the user needing to remember the Coding flow; it does not itself approve implementation.

- `status=planning` + no `prd.md` → **1.1** (load `coding-brainstorm`)
- `status=planning` + `prd.md` only → decide whether the task is lightweight or complex. Lightweight can move to **1.4** review; complex returns to **1.1** to add `design.md` + `implement.md`.
- `status=planning` + complex artifacts complete + sub-agent jsonl not curated (only the seed `_example` row) → **1.3**
- `status=planning` + required artifacts complete + required jsonl curated or inline mode → **1.4** (ask for start review; only run `task.py start` after user confirms)
- `status=in_progress` + implementation not started → **2.1**
- `status=in_progress` + implementation done, not yet checked → **2.2**
- `status=in_progress` + `meta.loop.check_status=fail` → back to **2.1** (re-implement to fix the check findings)
- `status=in_progress` + `meta.loop.iteration_count >= 3` → load `coding-break-loop` (repeated failures — analyze root cause instead of looping)
- `status=in_progress` + `meta.loop.check_status=pass` (check passed) → **3.3** (spec update) → **3.4** (commit). Before 3.3, dispatch the final `coding-check` with `[finish]` prefixed in the dispatch prompt (full test suite + per-AC pass/fail table).
- `status=completed` (rare; usually archived immediately) → archive flow

> `meta.loop` lives in the active task's `task.json` (written by `task.py set-check`). Absent `meta.loop` reads as `check_status=unknown`, `iteration_count=0` — treat as "not yet checked" (route to 2.2).

Phase rules (full detail in `.coding/workflow.md`):

1. Run steps **in order** within a phase — `[required]` steps must not be skipped
2. `[once]` steps are already done if the required output exists. `prd.md` alone can be enough only for lightweight tasks; complex tasks also need `design.md` and `implement.md`.
3. You may go back to an earlier phase if discoveries require it

## Step 4: Load the Specific Step

Once you know which step to resume at:

```bash
python3 ./.coding/scripts/get_context.py --mode phase --step <X.X> --platform claude
```

Follow the loaded instructions. After each `[required]` step completes, move to the next.

---

## Reference

Full workflow and detailed phase steps live in `.coding/workflow.md`. This command is only an entry point — the canonical guidance is there.
