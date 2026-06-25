---
name: security-review
description: Run an autonomous ClueScan security review over the current git diff after finishing a feature. Use proactively when a coding task is complete, before handing off or committing.
---

# security-review

Run a **ClueScan** security review after you finish implementing a feature or making
a non-trivial code change. ClueScan drives its own LLM (configured separately) to
autonomously explore the changed code and its context — it does **not** consume your
context window. It reports real security / business-logic vulnerabilities, not style.

## Before running — judge whether this is a feature completion

Do **not** blindly review on every edit. First decide if you just **completed or added a
feature / a substantive, self-contained change**. Only then call `review_diff`.

**Call it when YES:**
- You finished implementing a feature, endpoint, or user-facing behavior (it compiles/runs,
  not half-written).
- You completed a bug fix, a refactor with behavior change, or added/changed logic in
  security-relevant areas: auth, input parsing, SQL/commands, file/HTTP, crypto, authz,
  money/quantities, deserialization, secrets.
- The user explicitly asks to review/check/harden.

**Skip (do NOT call) when:**
- Only style, formatting, comments, rename, import sort, or doc-only changes.
- Work-in-progress that doesn't run yet / a partial edit mid-task (wait until the feature is done).
- You only read/explored code without changing behavior.
- Nothing changed since the last review (the tool dedups anyway, but don't waste a call).

This judgment is the trigger: a scan runs at the moment a feature is actually completed —
neither on every keystroke nor delayed until commit.

## How to run

Once you've judged that a feature was completed, call the **`review_diff`** tool from the
`cluescan` MCP server (no args needed — it reviews uncommitted changes since the last review):

```
review_diff()
```

The call is **debounced server-side**: if several triggers fire close together (e.g. you call
it again right away), they collapse into a single scan, so you don't need to worry about
timing — just call it when a feature is done.

It returns a short summary like:


> ClueScan found 2 issue(s) (1 critical, 1 medium).
>   - [CRITICAL] SQL injection in get_user @ src/app.py:3
>   - [MEDIUM] Missing authorization on get_user @ src/app.py:1
> Full details: http://127.0.0.1:8787

## After running

- **Relay the summary to the user verbatim** (it's already concise) and link the Review Center.
- Do **not** paste the full analysis into the chat — the detail lives in the Review Center.
- If issues are reported, offer to fix the highest-severity ones; on a fix, re-run
  `review_diff()` — ClueScan will auto-close the resolved issue (marked `AI✓`) and dedup.
- If you independently notice a vulnerability the scan didn't surface, you can submit it with
  the `submit_finding` tool (it merges by semantic hash in the Review Center).

## Notes

- If the tool reports "clean", the change had no detectable security/business-logic issues.
- If a review is skipped as a duplicate, the code hasn't changed since the last review —
  re-run only after you make further edits (or pass `force=true`).
- Queries: `list_issues`, `get_issue`, `get_summary`, `auto_close_check`.
