---
name: security-review
description: Run an autonomous ClueScan security review over the current git diff after finishing a feature. Use proactively when a coding task is complete, before handing off or committing.
---

# security-review

Run a **ClueScan** security review after you finish implementing a feature or making
a non-trivial code change. ClueScan drives its own LLM (configured separately) to
autonomously explore the changed code and its context — it does **not** consume your
context window. It reports real security / business-logic vulnerabilities, not style.

## When to use

Invoke this skill **proactively** when:
- you have just finished implementing a feature, fixing a bug, or refactoring code that
  touches security-relevant areas (auth, input handling, SQL/commands, crypto, file/HTTP,
  authorization, money/quantities, deserialization), **before** you summarize or hand off;
- the user asks you to "review", "check security", "scan", or "make sure this is safe".

Do **not** use it for pure style/formatting/typo changes or trivial doc edits.

## How to run

Call the **`review_diff`** tool provided by the `cluescan` MCP server (no arguments needed
for the common case — it reviews uncommitted changes since the last review):

```
review_diff()
```

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
