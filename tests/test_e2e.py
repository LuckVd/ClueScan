"""End-to-end: local MCP pipeline -> outbox -> HTTP sync -> live Review Center.

Only the LLM is stubbed (no API key needed). Everything else is real: git diff,
tree-sitter, explorer loop, analyzers, semantic dedup, local SQLite, outbox,
HTTP POST to a uvicorn-hosted center, the center's cross-source dedup + lifecycle.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from cluescan.config import load_config
from cluescan.llm import LLMClient, LLMResponse, TokenUsage
from cluescan.pipeline import run_review
from cluescan.lifecycle import run_autoclose
from cluescan.review_center import create_app
from cluescan.store import LocalStore
from cluescan.sync import drain_once


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class StubLLM(LLMClient):
    """Returns a SQLi finding for analysis; 'resolved' when verifying a fix."""
    def __init__(self):  # skip the real __init__ (no key needed)
        pass

    async def complete(self, messages, **kw):
        u = messages[-1]["content"]
        if "Has it been fixed?" in u:
            c = '{"verdict":"resolved","reason":"now parameterized"}'
        elif "BUSINESS-LOGIC" in u:
            c = '{"findings":[]}'
        elif "Audit this code change" in u:
            c = ('{"findings":[{"category":"sql_injection","severity":"critical","confidence":0.9,'
                 '"title":"SQL injection","description":"uid concatenated into query","fix_suggestion":"parameterize",'
                 '"file":"app.py","line":2,"function":"get_user","cwe":"CWE-89","source":"uid","sink":"query",'
                 '"data_flow":"uid -> query"}]}')
        else:
            c = '{"action":"done","evidence_summary":"uid is user-controlled, reaches query sink unsanitized"}'
        return LLMResponse(content=c, model="stub", usage=TokenUsage(3, 3, 6))

    async def close(self):
        pass


def _make_vuln_repo() -> str:
    d = tempfile.mkdtemp(prefix="cluescan_repo_")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=d, check=True)
    Path(d, "app.py").write_text('def get_user(uid):\n    return query("SELECT * FROM users WHERE id = %s", uid)\n')
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=d, check=True)
    # vulnerable change (uncommitted) -> the diff under review
    Path(d, "app.py").write_text(
        'def get_user(uid):\n    return query("SELECT * FROM users WHERE id = " + str(uid))\n'
    )
    return d


class Center:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        cfg = load_config()
        cfg.storage.center_db = db_path
        self._cfg = cfg
        config = uvicorn.Config(create_app(cfg), host="127.0.0.1", port=self.port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self):
        self._thread.start()
        for _ in range(100):
            try:
                httpx.get(f"{self.base}/api/v1/health", timeout=0.5)
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("center did not start")

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture
def stack():
    tmp = tempfile.mkdtemp(prefix="cluescan_e2e_")
    local_db = str(Path(tmp, "local.db"))
    center_db = str(Path(tmp, "center.db"))
    repo = _make_vuln_repo()
    cfg = load_config()
    cfg.storage.local_db = local_db
    cfg.ignore_patterns = []

    center = Center(center_db)
    center.start()
    cfg.sync.endpoint = center.base

    # register a project, capture its token for sync auth
    reg = httpx.post(f"{center.base}/api/v1/projects", json={"name": "demo", "repo": repo}).json()
    cfg.sync.auth_token = reg["token"]
    # persist registration locally so pipeline computes project name correctly
    asyncio.run(_save_reg(local_db, repo, reg["project"], reg["token"], center.base))

    yield {"cfg": cfg, "repo": repo, "center": center, "token": reg["token"]}

    center.stop()


async def _save_reg(local_db, repo, project, token, base):
    s = LocalStore(local_db)
    await s.connect()
    await s.save_registration(repo, project, token, base)
    await s.close()


def _drain(cfg):
    return asyncio.run(drain_once(cfg))


def test_review_syncs_to_center(stack):
    cfg, repo, center = stack["cfg"], stack["repo"], stack["center"]
    llm = StubLLM()

    r = asyncio.run(run_review(cfg, repo, llm=llm))
    assert r.new_issues >= 1 and not r.skipped_duplicate
    delivered = _drain(cfg)
    assert delivered >= 1

    issues = httpx.get(f"{center.base}/api/v1/issues").json()
    assert len(issues) == 1
    assert issues[0]["category"] == "sql_injection"
    assert "claude_code" in issues[0]["source_tools"]
    assert issues[0]["status"] == "open"


def test_trigger_dedup_skips_unchanged(stack):
    cfg, repo = stack["cfg"], stack["repo"]
    llm = StubLLM()
    asyncio.run(run_review(cfg, repo, llm=llm))           # first review
    r2 = asyncio.run(run_review(cfg, repo, llm=llm))      # no change
    assert r2.skipped_duplicate


def test_offline_then_sync(stack):
    cfg, repo, center = stack["cfg"], stack["repo"], stack["center"]
    llm = StubLLM()
    # stop the center -> review still works (offline-first), outbox retains
    center.stop()
    r = asyncio.run(run_review(cfg, repo, llm=llm, force=True))
    assert r.new_issues >= 1
    delivered = _drain(cfg)
    assert delivered == 0  # nothing shipped while center is down
    s = LocalStore(cfg.storage.local_db); asyncio.run(s.connect())
    pending = asyncio.run(s.pending()); asyncio.run(s.close())
    assert len(pending) >= 1  # retained for retry

    # restart center, drain again -> ships
    center2 = Center(stack["center"].db_path)
    center2.start()
    cfg.sync.endpoint = center2.base
    delivered = _drain(cfg)
    assert delivered >= 1
    issues = httpx.get(f"{center2.base}/api/v1/issues").json()
    assert len(issues) >= 1
    center2.stop()


def test_autoclose_flows_to_center(stack):
    cfg, repo, center = stack["cfg"], stack["repo"], stack["center"]
    llm = StubLLM()
    asyncio.run(run_review(cfg, repo, llm=llm))
    _drain(cfg)  # ship finding to center

    # fix the code, then auto-close
    Path(repo, "app.py").write_text(
        'def get_user(uid):\n    return query("SELECT * FROM users WHERE id = %s", uid)\n'
    )
    res = asyncio.run(run_autoclose(cfg, repo, llm=llm, files=["app.py"]))
    assert res["resolved"] >= 1
    _drain(cfg)  # ship autoclose

    issues = httpx.get(f"{center.base}/api/v1/issues").json()
    assert issues[0]["status"] == "fixed" and issues[0]["ai_closed"] == 1
    evs = httpx.get(f"{center.base}/api/v1/issues/{issues[0]['semantic_hash']}/events").json()
    assert any(e["event_type"] == "auto_closed" for e in evs)
