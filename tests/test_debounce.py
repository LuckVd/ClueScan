"""Tests for the MCP server-side trailing-edge debounce on review_diff.

The skill/caller may fire review_diff several times in quick succession; the
debounce must collapse a burst into ONE scan and hand every caller the same result.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import cluescan.mcp_server.server as srv
from cluescan.config import load_config
from cluescan.llm import LLMClient, LLMResponse, TokenUsage


class StubLLM(LLMClient):
    def __init__(self):
        pass

    async def complete(self, messages, **kw):
        u = messages[-1]["content"]
        if "BUSINESS-LOGIC" in u:
            c = '{"findings":[]}'
        elif "Audit this code change" in u:
            c = ('{"findings":[{"category":"sql_injection","severity":"critical","confidence":0.9,'
                 '"title":"SQLi","description":"x","file":"app.py","line":2,"function":"get_user",'
                 '"cwe":"CWE-89","source":"uid","sink":"query","data_flow":"uid->query"}]}')
        else:
            c = '{"action":"done","evidence_summary":"uid reaches query"}'
        return LLMResponse(content=c, model="stub", usage=TokenUsage(3, 3, 6))

    async def close(self):
        pass


def _vuln_repo() -> str:
    d = tempfile.mkdtemp(prefix="cluescan_db_")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=d, check=True)
    Path(d, "app.py").write_text('def get_user(uid):\n    return query("SELECT * FROM users WHERE id = %s", uid)\n')
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=d, check=True)
    Path(d, "app.py").write_text('def get_user(uid):\n    return query("SELECT * FROM users WHERE id = " + str(uid))\n')
    return d


def _ctx(debounce_ms: int):
    cfg = load_config()
    cfg.storage.local_db = tempfile.mktemp(prefix="cluescan_db_", suffix=".db")
    cfg.ignore_patterns = []
    cfg.triggers.debounce_ms = debounce_ms
    repo = _vuln_repo()
    ctx = srv._Ctx(cfg, repo)
    ctx._llm = StubLLM()
    ctx._tried_llm = True  # make llm() return the stub without building a real client
    return ctx, repo


def test_burst_collapses_into_one_scan():
    ctx, repo = _ctx(debounce_ms=300)
    real = srv.run_review
    calls = {"n": 0}

    async def counting(cfg, path, **kw):
        calls["n"] += 1
        return await real(cfg, path, **kw)

    srv.run_review = counting
    try:
        async def burst():
            return await asyncio.gather(*[ctx.debounced_review(repo) for _ in range(4)])
        results = asyncio.run(burst())
    finally:
        srv.run_review = real

    assert calls["n"] == 1, f"4 concurrent calls must collapse to 1 scan, got {calls['n']}"
    # every caller received the same result object
    assert all(r is results[0] for r in results)
    assert results[0].new_issues >= 1


def test_calls_outside_window_run_separately():
    ctx, repo = _ctx(debounce_ms=200)
    real = srv.run_review
    calls = {"n": 0}

    async def counting(cfg, path, **kw):
        calls["n"] += 1
        return await real(cfg, path, **kw)

    async def driver():
        await ctx.debounced_review(repo)              # burst 1
        await asyncio.sleep(0.35)                     # past the window
        await ctx.debounced_review(repo, force=True)  # burst 2 (force → not content-skipped)

    srv.run_review = counting
    try:
        asyncio.run(driver())
    finally:
        srv.run_review = real
    assert calls["n"] == 2, f"two separate windows -> 2 scans, got {calls['n']}"


def test_zero_debounce_runs_each_call():
    ctx, repo = _ctx(debounce_ms=0)
    real = srv.run_review
    calls = {"n": 0}

    async def counting(cfg, path, **kw):
        calls["n"] += 1
        return await real(cfg, path, **kw)

    srv.run_review = counting
    try:
        async def burst():
            return await asyncio.gather(*[ctx.debounced_review(repo) for _ in range(3)])
        asyncio.run(burst())
    finally:
        srv.run_review = real
    assert calls["n"] == 3, "debounce_ms<=0 disables coalescing"
