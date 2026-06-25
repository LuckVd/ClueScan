"""AI auto-close: re-verify open issues against the CURRENT code (locally).

Because the code lives at the dev machine (the center never holds source), the
"has this vulnerability been fixed?" check must run here. For each open Issue we
re-extract the function and ask the LLM whether the flaw is still exploitable.
`resolved` → mark fixed with ai_closed=True + reason, and enqueue an autoclose
record for the center. This only downgrades (never deletes) and is reversible —
if the vuln re-surfaces, a later review reopens it.
"""

from __future__ import annotations

from pathlib import Path

from cluescan.config import Config
from cluescan.context import CodeParser
from cluescan.llm import LLMClient, LLMError, extract_json
from cluescan.store import LocalStore
from cluescan.vcs import ChangeDetector

VERIFY_SYSTEM = """You are verifying whether a previously-reported security vulnerability has been FIXED.
You are given the original finding and the CURRENT code. Decide:
  - "resolved": the flaw is no longer exploitable (code removed, input now sanitized/parameterized,
    authorization added, secret removed, etc.)
  - "persists": the vulnerability is still present and exploitable.
Be strict: only "resolved" if the fix is effective. Respond with ONLY JSON:
{"verdict": "resolved" | "persists", "reason": "<one sentence>"}
"""


async def _verify_one(llm: LLMClient, parser: CodeParser, repo: Path, issue: dict) -> tuple[bool, str]:
    loc = issue.get("location") or {}
    file = loc.get("file")
    line = loc.get("line") or 1
    func = None
    current = "(file no longer exists)"
    if file:
        full = repo / file
        if full.exists():
            func = parser.enclosing_function(str(full), line)
            current = func.body if func else parser.line_range(str(full), max(1, line - 5), line + 5)
        else:
            return True, "source file removed — vulnerability no longer present"
    evidence = issue.get("evidence") or {}
    user = (
        f"Original finding:\n"
        f"- category: {issue.get('category')}\n"
        f"- title: {issue.get('title')}\n"
        f"- description: {issue.get('description')}\n"
        f"- sink: {evidence.get('sink')}\n- source: {evidence.get('source')}\n"
        f"- function: {loc.get('function')} @ {file}:{line}\n\n"
        f"CURRENT code:\n{current}\n\nHas it been fixed?"
    )
    try:
        resp = await llm.complete(
            [{"role": "system", "content": VERIFY_SYSTEM}, {"role": "user", "content": user}],
            json_mode=True, temperature=0.0,
        )
        data = await extract_json(resp.content)
    except (LLMError, Exception):
        return False, ""
    verdict = str(data.get("verdict", "")).lower()
    reason = str(data.get("reason", "")).strip()
    return verdict == "resolved", reason


async def run_autoclose(
    cfg: Config,
    repo_path: str,
    *,
    llm: LLMClient | None = None,
    files: list[str] | None = None,
) -> dict:
    repo = Path(repo_path).resolve()
    store = LocalStore(cfg.storage.local_db)
    await store.connect()
    owns_llm = llm is None
    checked = resolved = 0
    try:
        registration = await store.get_registration(str(repo))
        project = (registration.get("project") if registration else None) or Path(repo).name or "local"
        open_issues = await store.list_issues(str(repo), status="open")
        if files is not None:
            fset = set(files)
            open_issues = [i for i in open_issues if (i.get("location") or {}).get("file") in fset]
        if not open_issues:
            return {"checked": 0, "resolved": 0}

        if llm is None:
            llm = LLMClient(
                base_url=cfg.llm.base_url, api_key=cfg.llm.api_key, model=cfg.llm.model,
                max_tokens=cfg.llm.max_tokens, temperature=cfg.llm.temperature,
                timeout=cfg.llm.timeout, max_retries=cfg.llm.max_retries,
            )
        parser = CodeParser()
        for issue in open_issues:
            checked += 1
            is_resolved, reason = await _verify_one(llm, parser, repo, issue)
            if is_resolved and reason:
                resolved += 1
                await store.update_issue_status(
                    issue["semantic_hash"], status="fixed", ai_closed=True, ai_close_reason=reason,
                )
                await store.enqueue("autoclose", {
                    "semantic_hash": issue["semantic_hash"], "project": project, "repo": str(repo),
                    "issue_id": issue.get("issue_id"), "reason": reason,
                })
        return {"checked": checked, "resolved": resolved}
    finally:
        if owns_llm and llm is not None:
            await llm.close()
        await store.close()
