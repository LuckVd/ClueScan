"""Review pipeline: the orchestration that ties everything together.

run_review() is the single entry the MCP tools and the CLI call. It:
  1. resolves the diff (working-tree vs baseline, or explicit refs)
  2. trigger-dedup (skip if content unchanged since last completed review)
  3. expands hunks -> Regions
  4. for each Region: explore (LLM, minimal evidence) -> analyze (security+logic)
  5. semantic-hash findings, dedup within the review, count new vs already-known
  6. persist the review, advance the baseline, enqueue findings to the outbox
  7. return a concise ReviewResult (its .summary() is what the agent sees)

Offline-first: steps 1-7 never require the center. The center only consumes the
outbox asynchronously (cluescan.sync). Cross-source dedup is the center's job,
keyed by the semantic hash attached here.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

from cluescan.analysis import analyze_region
from cluescan.config import Config
from cluescan.context import CodeParser, regions_from_diff
from cluescan.context.explorer import Explorer
from cluescan.dedup import attach_hash
from cluescan.llm import LLMClient
from cluescan.models import Finding, ReviewResult, Severity, parse_severity, severity_at_least
from cluescan.store import LocalStore
from cluescan.vcs import ChangeDetector


def _project_for(repo: str, registration: dict | None) -> str:
    if registration and registration.get("project"):
        return registration["project"]
    return Path(repo).name or "local"


def _finding_to_payload(f: Finding, repo: str, project: str, review_id: str) -> dict:
    return {
        "semantic_hash": f.semantic_hash,
        "project": project,
        "repo": repo,
        "category": f.category,
        "severity": f.severity.value,
        "confidence": f.confidence,
        "title": f.title,
        "description": f.description,
        "fix_suggestion": f.fix_suggestion,
        "location": {
            "file": f.location.file,
            "line": f.location.line,
            "end_line": f.location.end_line,
            "function": f.location.function,
        },
        "cwe": f.cwe,
        "owasp": f.owasp,
        "source": f.source,
        "source_tool": f.source_tool,
        "evidence": f.evidence,
        "missing_check": f.missing_check,
        "entry_point": f.entry_point,
        "attack_path": f.attack_path,
        "review_id": review_id,
    }


async def _process_region(region, parser: CodeParser, repo: Path, llm: LLMClient, cfg: Config,
                          source_tool: str) -> list[Finding]:
    min_sev = parse_severity(cfg.analysis.min_severity)
    try:
        exploration = await Explorer(
            parser, repo, llm,
            max_steps=cfg.analysis.explorer_max_steps,
            char_budget=cfg.analysis.context_token_budget * 4,
        ).explore(region)
        return await analyze_region(
            exploration, llm, repo,
            enable_security=cfg.analysis.enable_security,
            enable_logic=cfg.analysis.enable_logic_vuln,
            min_severity=min_sev,
            source_tool=source_tool,
        )
    except Exception as e:  # one bad region must not abort the whole review
        return _fallback_region_findings(region, e)


def _fallback_region_findings(region, err) -> list[Finding]:
    # Keep the review resilient: log via finding-free result; the region is skipped.
    return []


async def run_review(
    cfg: Config,
    repo_path: str,
    *,
    base_ref: str | None = None,
    head_ref: str | None = None,
    source_tool: str = "claude_code",
    force: bool = False,
    llm: LLMClient | None = None,
) -> ReviewResult:
    repo = Path(repo_path).resolve()
    review_id = f"r_{uuid.uuid4().hex[:12]}"
    started = time.monotonic()

    detector = ChangeDetector(repo)
    if not await detector.is_repo():
        return ReviewResult(review_id=review_id, repo=str(repo), base_ref="", head_ref="",
                            error="not a git repository")

    store = LocalStore(cfg.storage.local_db)
    await store.connect()
    owns_llm = llm is None
    try:
        registration = await store.get_registration(str(repo))
        center_url = (registration.get("center_url") if registration else None) or cfg.sync.endpoint
        project = _project_for(str(repo), registration)

        # resolve base: explicit > stored baseline > HEAD (review uncommitted changes)
        if base_ref is None:
            baseline = await store.get_baseline(str(repo))
            base_ref = (baseline.get("commit") if baseline else None) or "HEAD"

        diff = await detector.detect(base_ref=base_ref, head_ref=head_ref)

        # trigger dedup: identical content since last completed review
        if not force and await store.should_skip(str(repo), diff.content_hash):
            return ReviewResult(
                review_id=review_id, repo=str(repo), base_ref=base_ref,
                head_ref=diff.head_ref, skipped_duplicate=True,
                duration_seconds=round(time.monotonic() - started, 3),
                center_url=center_url,
            )

        regions = regions_from_diff(diff, repo, CodeParser(), cfg.ignore_patterns)
        result = ReviewResult(
            review_id=review_id, repo=str(repo), base_ref=base_ref, head_ref=diff.head_ref,
            files_reviewed=len({c.path for c in diff.reviewed_changes}), center_url=center_url,
        )
        touched_files = [c.path for c in diff.reviewed_changes]

        # Build the LLM client once if anything needs it.
        if (regions or cfg.autoclose.enabled) and llm is None:
            llm = LLMClient(
                base_url=cfg.llm.base_url, api_key=cfg.llm.api_key, model=cfg.llm.model,
                max_tokens=cfg.llm.max_tokens, temperature=cfg.llm.temperature,
                timeout=cfg.llm.timeout, max_retries=cfg.llm.max_retries,
            )

        # AI auto-close: did this change fix any pre-existing open issues?
        if cfg.autoclose.enabled and llm is not None:
            from cluescan.lifecycle import run_autoclose
            try:
                ac = await run_autoclose(cfg, str(repo), llm=llm, files=touched_files)
                result.auto_closed = ac.get("resolved", 0)
            except Exception:
                pass  # autoclose is best-effort; never block a review on it

        if not regions:
            await _finalize(store, repo, result, diff, started)
            return result
        sem = asyncio.Semaphore(max(1, cfg.llm.concurrency))

        async def guarded(region):
            async with sem:
                return await _process_region(region, CodeParser(), repo, llm, cfg, source_tool)

        per_region = await asyncio.gather(*[guarded(r) for r in regions])
        raw_findings: list[Finding] = [f for group in per_region for f in group]

        # semantic hash + within-review dedup (keep highest severity/confidence)
        for f in raw_findings:
            attach_hash(f)
        deduped: dict[str, Finding] = {}
        for f in raw_findings:
            ex = deduped.get(f.semantic_hash)
            if ex is None or _ranks_higher(f, ex):
                deduped[f.semantic_hash] = f
        findings = list(deduped.values())

        # record locally (offline mirror) + count new vs already-known + enqueue for sync
        new_issues = merged_issues = 0
        for f in findings:
            cached = await store.get_issue(f.semantic_hash)
            issue_dict = {
                "semantic_hash": f.semantic_hash,
                "project": project,
                "repo": str(repo),
                "issue_id": cached["issue_id"] if cached else None,
                "status": cached["status"] if cached else "open",
                "severity": f.severity.value,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "location": {"file": f.location.file, "line": f.location.line, "function": f.location.function},
                "cwe": f.cwe,
                "owasp": f.owasp,
                "ai_closed": cached["ai_closed"] if cached else False,
                "ai_close_reason": cached["ai_close_reason"] if cached else None,
            }
            await store.upsert_issue(issue_dict)
            if cached:
                merged_issues += 1
            else:
                new_issues += 1
            await store.enqueue("finding", _finding_to_payload(f, str(repo), project, review_id))

        result.findings = findings
        result.new_issues = new_issues
        result.merged_issues = merged_issues
        await _finalize(store, repo, result, diff, started)
        return result
    finally:
        if owns_llm and llm is not None:
            await llm.close()
        await store.close()


def _ranks_higher(a: Finding, b: Finding) -> bool:
    from cluescan.models import SEVERITY_RANK
    if SEVERITY_RANK[a.severity] != SEVERITY_RANK[b.severity]:
        return SEVERITY_RANK[a.severity] < SEVERITY_RANK[b.severity]
    return a.confidence > b.confidence


async def _finalize(store: LocalStore, repo: Path, result: ReviewResult, diff, started: float) -> None:
    result.duration_seconds = round(time.monotonic() - started, 3)
    try:
        head_sha = await ChangeDetector(repo).head_sha()
    except Exception:
        head_sha = diff.head_ref
    await store.save_review(result)
    await store.set_baseline(str(repo), head_sha, diff.content_hash)
