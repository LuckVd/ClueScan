"""Local MCP Server (FastMCP, stdio) — the execution core AI agents connect to.

Every tool does its work inside ClueScan's own process with ClueScan's own LLM;
nothing leaks into the calling agent's context window except the short summary we
choose to return. The primary entry, review_diff, returns a brief one-liner the
agent can relay; full detail lives in the Review Center.

The server also opportunistically drains the outbox after writes (offline-first:
a dead center never blocks a review), and `cluescan sync` drains it explicitly.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from cluescan.config import Config, load_config
from cluescan.context import CodeParser
from cluescan.context.regions import Region
from cluescan.context.explorer import Explorer
from cluescan.analysis import analyze_region
from cluescan.dedup import attach_hash, semantic_hash
from cluescan.lifecycle import run_autoclose
from cluescan.llm import LLMClient
from cluescan.models import Severity, parse_severity
from cluescan.pipeline import run_review
from cluescan.store import LocalStore
from cluescan.sync import drain_once


class _Ctx:
    """Shared server state: config, repo, a lazily-built LLM client."""

    def __init__(self, cfg: Config, repo: str):
        self.cfg = cfg
        self.repo = repo
        self._llm: LLMClient | None = None
        self._tried_llm = False
        # per-repo trailing-edge debounce state for review_diff
        self._debounce: dict[str, dict] = {}

    async def llm(self) -> LLMClient:
        if self._llm is None and not self._tried_llm:
            self._tried_llm = True
            self._llm = LLMClient(
                base_url=self.cfg.llm.base_url, api_key=self.cfg.llm.api_key, model=self.cfg.llm.model,
                max_tokens=self.cfg.llm.max_tokens, temperature=self.cfg.llm.temperature,
                timeout=self.cfg.llm.timeout, max_retries=self.cfg.llm.max_retries,
            )
        return self._llm

    def fire_and_forget_drain(self) -> None:
        try:
            asyncio.get_running_loop().create_task(drain_once(self.cfg))
        except RuntimeError:
            pass

    async def debounced_review(self, repo: str, *, base_ref: str | None = None,
                               head_ref: str | None = None, force: bool = False,
                               source_tool: str = "claude_code"):
        """Trailing-edge debounce: many review_diff calls within `debounce_ms`
        collapse into ONE review (the latest args win); every caller awaits and
        receives the same ReviewResult. With debounce_ms <= 0, runs immediately."""
        from cluescan.models import ReviewResult
        debounce_s = self.cfg.triggers.debounce_ms / 1000.0
        if debounce_s <= 0:
            llm = await self.llm()
            return await run_review(self.cfg, repo, base_ref=base_ref, head_ref=head_ref,
                                    source_tool=source_tool, force=force, llm=llm)

        st = self._debounce.setdefault(repo, {"task": None, "waiters": [], "kw": None, "fires": 0.0})
        kw = {"base_ref": base_ref, "head_ref": head_ref, "force": force, "source_tool": source_tool}
        now = time.monotonic()
        if st["task"] is None or st["fires"] <= now:
            # (re)schedule a trailing-edge review `debounce_s` out
            st["fires"] = now + debounce_s
            st["kw"] = kw
            st["task"] = asyncio.create_task(self._debounce_runner(repo))
        else:
            # inside the window: latest args win, join the in-flight review
            st["kw"] = kw
        fut = asyncio.get_running_loop().create_future()
        st["waiters"].append(fut)
        return await fut

    async def _debounce_runner(self, repo: str):
        from cluescan.models import ReviewResult
        st = self._debounce[repo]
        debounce_s = self.cfg.triggers.debounce_ms / 1000.0
        try:
            await asyncio.sleep(debounce_s)
            kw = st["kw"] or {}
            llm = await self.llm()
            result = await run_review(self.cfg, repo, llm=llm, **kw)
        except Exception as e:
            result = ReviewResult(review_id="err", repo=repo, base_ref="", head_ref="",
                                  error=f"debounced review failed: {e}")
        waiters, st["waiters"] = st.get("waiters", []), []
        st["task"] = None
        st["fires"] = 0.0
        for f in waiters:
            if not f.done():
                f.set_result(result)


def _resolve_repo(ctx: _Ctx, repo: str | None) -> str:
    return str(Path(repo).resolve()) if repo else ctx.repo


def build_mcp(cfg: Config, repo: str) -> FastMCP:
    ctx = _Ctx(cfg, repo)
    mcp = FastMCP("cluescan")

    # -- reviews ----------------------------------------------------------
    @mcp.tool()
    async def review_diff(
        base_ref: str | None = None,
        head_ref: str | None = None,
        repo: str | None = None,
        force: bool = False,
    ) -> str:
        """Run a security review over the repo's git diff (default: uncommitted
        changes since the last review). Returns a short summary; full detail is
        in the Review Center. Call this after finishing a feature. Repeated calls
        within the debounce window collapse into one scan; pass force=true to
        bypass dedup and re-review identical content."""
        result = await ctx.debounced_review(
            _resolve_repo(ctx, repo), base_ref=base_ref, head_ref=head_ref, force=force,
        )
        ctx.fire_and_forget_drain()
        return result.summary()

    @mcp.tool()
    async def review_code(code: str, language: str = "python", file: str = "snippet.py") -> str:
        """Review an in-memory code snippet for vulnerabilities (no git needed).
        Useful when the agent wants a quick check without a diff."""
        llm = await ctx.llm()
        region = Region(file=file, language=language, function_name=None,
                        function_body=code, changed_snippet=code, entry_point=(False, None))
        exploration = await Explorer(
            CodeParser(), Path(ctx.repo), llm, max_steps=cfg.analysis.explorer_max_steps,
            char_budget=cfg.analysis.context_token_budget * 4,
        ).explore(region)
        findings = await analyze_region(
            exploration, llm, Path(ctx.repo),
            enable_security=cfg.analysis.enable_security, enable_logic=cfg.analysis.enable_logic_vuln,
            min_severity=parse_severity(cfg.analysis.min_severity), source_tool="claude_code",
        )
        if not findings:
            return f"ClueScan: clean snippet ({len(findings)} issues)."
        lines = [f"ClueScan found {len(findings)} issue(s) in the snippet:"]
        for f in findings[:8]:
            lines.append(f"  - [{f.severity.value.upper()}] {f.title}: {f.description[:160]}")
        return "\n".join(lines)

    @mcp.tool()
    async def auto_close_check(repo: str | None = None) -> str:
        """Re-verify open issues for this repo against the current code and
        auto-close any that have been fixed (marked ai_closed)."""
        llm = await ctx.llm()
        res = await run_autoclose(cfg, _resolve_repo(ctx, repo), llm=llm)
        ctx.fire_and_forget_drain()
        return f"Auto-close check: verified {res['checked']} open issue(s); closed {res['resolved']} as fixed."

    # -- issue queries / lifecycle ---------------------------------------
    async def _store() -> LocalStore:
        s = LocalStore(cfg.storage.local_db)
        await s.connect()
        return s

    @mcp.tool()
    async def list_issues(
        repo: str | None = None, status: str | None = None, severity: str | None = None,
    ) -> list[dict]:
        """List known issues for a repo (local mirror of the Review Center)."""
        s = await _store()
        try:
            rows = await s.list_issues(_resolve_repo(ctx, repo), status=status)
        finally:
            await s.close()
        if severity:
            rows = [r for r in rows if r.get("severity") == severity]
        return rows

    @mcp.tool()
    async def get_issue(semantic_hash: str) -> dict | str:
        """Get full detail for one issue by its semantic hash."""
        s = await _store()
        try:
            issue = await s.get_issue(semantic_hash)
        finally:
            await s.close()
        return issue or f"No issue with hash {semantic_hash}"

    @mcp.tool()
    async def update_issue_status(
        semantic_hash: str, status: str, comment: str | None = None, repo: str | None = None,
    ) -> str:
        """Change an issue's status (open|confirmed|fixing|fixed|wontfix|false_positive).
        Synced to the Review Center asynchronously."""
        s = await _store()
        try:
            await s.update_issue_status(semantic_hash, status)
            reg = await s.get_registration(_resolve_repo(ctx, repo))
            project = (reg.get("project") if reg else None) or Path(ctx.repo).name
            await s.enqueue("status_change", {
                "semantic_hash": semantic_hash, "project": project, "repo": _resolve_repo(ctx, repo),
                "status": status, "comment": comment,
            })
        finally:
            await s.close()
        ctx.fire_and_forget_drain()
        return f"Issue {semantic_hash} -> {status}"

    @mcp.tool()
    async def get_summary(repo: str | None = None) -> dict:
        """A quick overview of issues for a repo (counts by severity/status)."""
        s = await _store()
        try:
            rows = await s.list_issues(_resolve_repo(ctx, repo))
        finally:
            await s.close()
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in rows:
            by_sev[r.get("severity", "?")] = by_sev.get(r.get("severity", "?"), 0) + 1
            by_status[r.get("status", "?")] = by_status.get(r.get("status", "?"), 0) + 1
        return {"total": len(rows), "by_severity": by_sev, "by_status": by_status}

    @mcp.tool()
    async def submit_finding(
        category: str, severity: str, title: str, description: str,
        file: str, line: int, function: str | None = None, cwe: str | None = None,
        sink: str | None = None, source: str | None = None, source_tool: str = "manual",
        repo: str | None = None,
    ) -> str:
        """Submit a finding you noticed yourself (cross-tool aggregation). The
        Review Center merges it by semantic hash with any matching issue."""
        from cluescan.models import CodeLocation, Finding
        repo_r = _resolve_repo(ctx, repo)
        f = Finding(
            category=category, severity=parse_severity(severity), title=title, description=description,
            location=CodeLocation(file=file, line=line, function=function), cwe=cwe,
            source="agent", source_tool=source_tool,
            evidence={"sink": sink, "source": source} if (sink or source) else {},
        )
        attach_hash(f)
        s = await _store()
        try:
            reg = await s.get_registration(repo_r)
            project = (reg.get("project") if reg else None) or Path(repo_r).name
            await s.enqueue("finding", {
                "semantic_hash": f.semantic_hash, "project": project, "repo": repo_r,
                "category": f.category, "severity": f.severity.value, "confidence": f.confidence,
                "title": f.title, "description": f.description, "fix_suggestion": f.fix_suggestion,
                "location": {"file": file, "line": line, "function": function},
                "cwe": cwe, "owasp": None, "source": "agent", "source_tool": source_tool,
                "evidence": f.evidence, "missing_check": None, "entry_point": None, "attack_path": None,
                "review_id": None,
            })
            cached = await s.get_issue(f.semantic_hash)
            await s.upsert_issue({
                "semantic_hash": f.semantic_hash, "project": project, "repo": repo_r,
                "issue_id": cached["issue_id"] if cached else None,
                "status": cached["status"] if cached else "open",
                "severity": f.severity.value, "category": f.category, "title": f.title,
                "description": f.description, "evidence": f.evidence,
                "location": {"file": file, "line": line, "function": function},
                "cwe": cwe, "owasp": None,
                "ai_closed": cached["ai_closed"] if cached else False,
                "ai_close_reason": cached["ai_close_reason"] if cached else None,
            })
        finally:
            await s.close()
        ctx.fire_and_forget_drain()
        action = "merged into existing" if cached else "created new"
        return f"Finding '{title}' {action} issue {f.semantic_hash}."

    @mcp.resource("config://cluescan")
    def config_resource() -> str:  # type: ignore[unused]
        """Current ClueScan configuration (model, endpoint, thresholds)."""
        c = cfg
        return (
            f"model={c.llm.model} base_url={c.llm.base_url} concurrency={c.llm.concurrency} "
            f"min_severity={c.analysis.min_severity} languages={c.analysis.languages} "
            f"autoclose={c.autoclose.enabled} center={c.sync.endpoint}"
        )

    return mcp


def _default_repo() -> str:
    return str(Path(os.environ.get("CLUESCAN_REPO", os.getcwd())).resolve())


def run_stdio(cfg: Config | None = None) -> None:
    cfg = cfg or load_config()
    mcp = build_mcp(cfg, _default_repo())
    mcp.run(transport=cfg.mcp.transport)
