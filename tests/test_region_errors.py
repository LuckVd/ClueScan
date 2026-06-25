"""A failed/hanging LLM must never produce a silent false 'clean'.

Covers the regression: _process_region used to swallow LLM errors and return [],
and run_review had no time bound — so the debounce path could hang for minutes
and then report 'clean'. Now region failures are counted (region_errors) and a
per-region timeout bounds the hang.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
import time
from pathlib import Path

from cluescan.config import load_config
from cluescan.llm import LLMClient, LLMError, LLMResponse, TokenUsage
from cluescan.pipeline import run_review


def _vuln_repo() -> str:
    d = tempfile.mkdtemp(prefix="cluescan_re_")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=d, check=True)
    Path(d, "app.py").write_text('def get_user(uid):\n    return query("SELECT * FROM users WHERE id = %s", uid)\n')
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=d, check=True)
    Path(d, "app.py").write_text('def get_user(uid):\n    return query("SELECT * FROM users WHERE id = " + str(uid))\n')
    return d


def _cfg(region_timeout: int):
    cfg = load_config()
    cfg.storage.local_db = tempfile.mktemp(prefix="cluescan_re_", suffix=".db")
    cfg.ignore_patterns = []
    cfg.autoclose.enabled = False
    cfg.analysis.region_timeout_seconds = region_timeout
    return cfg


class ErrorLLM(LLMClient):
    def __init__(self):
        pass

    async def complete(self, messages, **kw):
        raise LLMError("LLM is down")

    async def close(self):
        pass


class HangLLM(LLMClient):
    def __init__(self, delay: float = 5.0):
        self.delay = delay

    async def complete(self, messages, **kw):
        await asyncio.sleep(self.delay)
        return LLMResponse(content='{"action":"done","evidence_summary":"x"}', model="stub",
                           usage=TokenUsage(1, 1, 2))

    async def close(self):
        pass


def test_llm_failure_is_not_silent_clean():
    cfg = _cfg(region_timeout=90)
    repo = _vuln_repo()
    r = asyncio.run(run_review(cfg, repo, llm=ErrorLLM()))
    assert r.region_errors >= 1, "an LLM failure must be counted as a region error"
    assert r.findings == []
    assert "INCOMPLETE" in r.summary(), r.summary()
    assert "clean" not in r.summary().lower()


def test_hanging_llm_is_bounded_by_region_timeout():
    cfg = _cfg(region_timeout=1)          # 1s cap per region
    repo = _vuln_repo()
    start = time.monotonic()
    r = asyncio.run(run_review(cfg, repo, llm=HangLLM(delay=5)))
    elapsed = time.monotonic() - start
    assert r.region_errors >= 1, "a hanging region must be counted as a region error"
    assert elapsed < 4, f"region timeout must bound the hang; took {elapsed:.1f}s"
    assert "INCOMPLETE" in r.summary()
