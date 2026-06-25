"""Local SQLite store for the MCP core.

Holds everything the local side needs to be self-sufficient offline:
  * reviews        — history of every review run
  * baselines      — last-reviewed commit + content hash per repo (trigger dedup)
  * outbox         — findings/reviews queued for async sync to the center
  * issue_cache    — local mirror of the center's Issues (for listing + autoclose)
  * registrations  — repo ↔ project/token binding (from `cluescan register`)

Single persistent async connection (aiosqlite), WAL mode, busy_timeout.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    review_id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    base_ref TEXT,
    head_ref TEXT,
    content_hash TEXT,
    created_at TEXT NOT NULL,
    files_reviewed INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    new_issues INTEGER DEFAULT 0,
    merged_issues INTEGER DEFAULT 0,
    auto_closed INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS baselines (
    repo TEXT PRIMARY KEY,
    commit_sha TEXT,
    content_hash TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    next_retry TEXT,
    status TEXT DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(status, next_retry);
CREATE TABLE IF NOT EXISTS issue_cache (
    semantic_hash TEXT PRIMARY KEY,
    project TEXT,
    repo TEXT,
    issue_id TEXT,
    status TEXT,
    severity TEXT,
    category TEXT,
    title TEXT,
    description TEXT,
    evidence TEXT,
    file TEXT,
    line INTEGER,
    function TEXT,
    cwe TEXT,
    owasp TEXT,
    ai_closed INTEGER DEFAULT 0,
    ai_close_reason TEXT,
    last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_issue_repo_status ON issue_cache(repo, status);
CREATE TABLE IF NOT EXISTS registrations (
    repo TEXT PRIMARY KEY,
    project TEXT,
    token TEXT,
    center_url TEXT,
    updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(os.path.expanduser(str(db_path)))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> "LocalStore":
        if self._db is None:
            self._db = await aiosqlite.connect(str(self.db_path))
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA busy_timeout=5000")
            await self._db.executescript(_SCHEMA)
            await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> "LocalStore":
        return await self.connect()

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    def _require(self) -> aiosqlite.Connection:
        assert self._db is not None, "LocalStore.connect() not called"
        return self._db

    # -- registrations ----------------------------------------------------
    async def save_registration(self, repo: str, project: str, token: str, center_url: str) -> None:
        db = self._require()
        await db.execute(
            "INSERT INTO registrations(repo, project, token, center_url, updated_at) "
            "VALUES(?,?,?,?,?) ON CONFLICT(repo) DO UPDATE SET "
            "project=excluded.project, token=excluded.token, center_url=excluded.center_url, updated_at=excluded.updated_at",
            (repo, project, token, center_url, _now()),
        )
        await db.commit()

    async def get_registration(self, repo: str) -> dict[str, Any] | None:
        db = self._require()
        cur = await db.execute("SELECT project, token, center_url FROM registrations WHERE repo=?", (repo,))
        row = await cur.fetchone()
        if not row:
            return None
        return {"project": row[0], "token": row[1], "center_url": row[2]}

    # -- baselines / trigger dedup ---------------------------------------
    async def get_baseline(self, repo: str) -> dict[str, Any] | None:
        db = self._require()
        cur = await db.execute("SELECT commit_sha, content_hash, updated_at FROM baselines WHERE repo=?", (repo,))
        row = await cur.fetchone()
        if not row:
            return None
        return {"commit": row[0], "content_hash": row[1], "updated_at": row[2]}

    async def set_baseline(self, repo: str, commit: str, content_hash: str) -> None:
        db = self._require()
        await db.execute(
            "INSERT INTO baselines(repo, commit_sha, content_hash, updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(repo) DO UPDATE SET commit_sha=excluded.commit_sha, "
            "content_hash=excluded.content_hash, updated_at=excluded.updated_at",
            (repo, commit, content_hash, _now()),
        )
        await db.commit()

    async def should_skip(self, repo: str, content_hash: str) -> bool:
        """Skip if the last completed review for this repo saw identical content."""
        base = await self.get_baseline(repo)
        return bool(base and base.get("content_hash") == content_hash and content_hash)

    # -- reviews ----------------------------------------------------------
    async def save_review(self, rr) -> None:
        db = self._require()
        await db.execute(
            "INSERT OR REPLACE INTO reviews(review_id, repo, base_ref, head_ref, content_hash, created_at, "
            "files_reviewed, finding_count, new_issues, merged_issues, auto_closed, duration, error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rr.review_id, rr.repo, rr.base_ref, rr.head_ref, None, _now(),
             rr.files_reviewed, len(rr.findings), rr.new_issues, rr.merged_issues,
             rr.auto_closed, rr.duration_seconds, rr.error),
        )
        await db.commit()

    # -- outbox -----------------------------------------------------------
    async def enqueue(self, kind: str, payload: dict[str, Any]) -> int:
        db = self._require()
        cur = await db.execute(
            "INSERT INTO outbox(kind, payload, created_at, status) VALUES(?,?,?,'pending')",
            (kind, json.dumps(payload, default=str), _now()),
        )
        await db.commit()
        return cur.lastrowid or 0

    async def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        """All pending outbox records (a sync attempt tries each; next_retry is
        informational and reserved for future auto-throttling)."""
        db = self._require()
        cur = await db.execute(
            "SELECT id, kind, payload, attempts FROM outbox WHERE status='pending' "
            "ORDER BY id LIMIT ?",
            (limit,),
        )
        rows = await cur.fetchall()
        return [{"id": r[0], "kind": r[1], "payload": json.loads(r[2]), "attempts": r[3]} for r in rows]

    async def mark_done(self, outbox_id: int) -> None:
        db = self._require()
        await db.execute("UPDATE outbox SET status='done' WHERE id=?", (outbox_id,))
        await db.commit()

    async def schedule_retry(self, outbox_id: int, next_retry: str, attempts: int) -> None:
        db = self._require()
        await db.execute(
            "UPDATE outbox SET attempts=?, next_retry=? WHERE id=?", (attempts, next_retry, outbox_id)
        )
        await db.commit()

    # -- issue cache (mirror of the center) ------------------------------
    async def upsert_issue(self, issue: dict[str, Any]) -> None:
        db = self._require()
        loc = issue.get("location") or {}
        evidence = issue.get("evidence")
        evidence_json = json.dumps(evidence) if isinstance(evidence, dict) else (evidence or None)
        await db.execute(
            "INSERT INTO issue_cache(semantic_hash, project, repo, issue_id, status, severity, category, "
            "title, description, evidence, file, line, function, cwe, owasp, ai_closed, ai_close_reason, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(semantic_hash) DO UPDATE SET status=excluded.status, severity=excluded.severity, "
            "title=excluded.title, description=COALESCE(excluded.description, issue_cache.description), "
            "evidence=COALESCE(excluded.evidence, issue_cache.evidence), "
            "ai_closed=excluded.ai_closed, ai_close_reason=excluded.ai_close_reason, "
            "last_seen=excluded.last_seen, issue_id=COALESCE(excluded.issue_id, issue_cache.issue_id)",
            (issue["semantic_hash"], issue.get("project"), issue.get("repo"), issue.get("issue_id"),
             issue.get("status", "open"), issue.get("severity"), issue.get("category"), issue.get("title"),
             issue.get("description"), evidence_json,
             loc.get("file"), loc.get("line"), loc.get("function"),
             issue.get("cwe"), issue.get("owasp"),
             int(bool(issue.get("ai_closed"))), issue.get("ai_close_reason"), _now()),
        )
        await db.commit()

    async def get_issue(self, semantic_hash: str) -> dict[str, Any] | None:
        db = self._require()
        cur = await db.execute(
            "SELECT semantic_hash, project, repo, issue_id, status, severity, category, title, description, "
            "evidence, file, line, function, cwe, owasp, ai_closed, ai_close_reason FROM issue_cache "
            "WHERE semantic_hash=?",
            (semantic_hash,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        ev = None
        if row[9]:
            try:
                ev = json.loads(row[9])
            except (json.JSONDecodeError, TypeError):
                ev = None
        return {"semantic_hash": row[0], "project": row[1], "repo": row[2], "issue_id": row[3],
                "status": row[4], "severity": row[5], "category": row[6], "title": row[7],
                "description": row[8], "evidence": ev,
                "location": {"file": row[10], "line": row[11], "function": row[12]},
                "cwe": row[13], "owasp": row[14], "ai_closed": bool(row[15]), "ai_close_reason": row[16]}

    async def list_issues(self, repo: str, *, status: str | None = None) -> list[dict[str, Any]]:
        db = self._require()
        sql = ("SELECT semantic_hash, project, issue_id, status, severity, category, title, description, "
               "file, line, function, ai_closed, ai_close_reason FROM issue_cache WHERE repo=?")
        params: list[Any] = [repo]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY rowid DESC"
        cur = await db.execute(sql, params)
        rows = await cur.fetchall()
        return [{"semantic_hash": r[0], "project": r[1], "issue_id": r[2], "status": r[3], "severity": r[4],
                 "category": r[5], "title": r[6], "description": r[7],
                 "location": {"file": r[8], "line": r[9], "function": r[10]},
                 "ai_closed": bool(r[11]), "ai_close_reason": r[12]} for r in rows]

    async def update_issue_status(self, semantic_hash: str, status: str,
                                  ai_closed: bool | None = None, ai_close_reason: str | None = None) -> None:
        db = self._require()
        sets = ["status=?"]
        params: list[Any] = [status]
        if ai_closed is not None:
            sets.append("ai_closed=?")
            params.append(int(ai_closed))
        if ai_close_reason is not None:
            sets.append("ai_close_reason=?")
            params.append(ai_close_reason)
        params.append(semantic_hash)
        await db.execute(f"UPDATE issue_cache SET {', '.join(sets)} WHERE semantic_hash=?", params)
        await db.commit()
