"""Review Center storage — the canonical Issue store (the "middle platform").

The center owns the full Issue lifecycle and does cross-source dedup by semantic
hash: the same vulnerability reported by Claude Code, Cursor, etc. collapses to
one Issue whose source_tools accumulates. It also records an event trail
(created / re_detected / status_changed / auto_closed / reopened).
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    name TEXT PRIMARY KEY,
    repo TEXT,
    token TEXT UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issues (
    semantic_hash TEXT PRIMARY KEY,
    project TEXT,
    repo TEXT,
    category TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    evidence TEXT,
    file TEXT,
    line INTEGER,
    function TEXT,
    cwe TEXT,
    owasp TEXT,
    status TEXT DEFAULT 'open',
    ai_closed INTEGER DEFAULT 0,
    ai_close_reason TEXT,
    source_tools TEXT DEFAULT '[]',
    detection_count INTEGER DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_review_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_issues_project ON issues(project);
CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity);
CREATE TABLE IF NOT EXISTS issue_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    semantic_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    details TEXT,
    source_tool TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_hash ON issue_events(semantic_hash, id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CenterStore:
    def __init__(self, db_path: str):
        from pathlib import Path
        self.db_path = str(Path(db_path).expanduser())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> "CenterStore":
        if self._db is None:
            self._db = await aiosqlite.connect(self.db_path)
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA busy_timeout=5000")
            self._db.row_factory = aiosqlite.Row
            await self._db.executescript(_SCHEMA)
            await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _db_ref(self) -> aiosqlite.Connection:
        assert self._db is not None, "CenterStore.connect() not called"
        return self._db

    # -- projects ---------------------------------------------------------
    async def create_project(self, name: str, repo: str) -> dict[str, Any]:
        db = self._db_ref()
        token = secrets.token_urlsafe(24)
        now = _now()
        await db.execute(
            "INSERT INTO projects(name, repo, token, created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET repo=excluded.repo",
            (name, repo, token, now),
        )
        await db.commit()
        cur = await db.execute("SELECT name, token FROM projects WHERE name=?", (name,))
        row = await cur.fetchone()
        return {"project": row["name"], "token": row["token"]}

    async def list_projects(self) -> list[dict[str, Any]]:
        db = self._db_ref()
        cur = await db.execute("SELECT name, repo, created_at FROM projects ORDER BY created_at DESC")
        return [dict(r) for r in await cur.fetchall()]

    async def is_valid_token(self, token: str | None) -> bool:
        if not token:
            return False
        db = self._db_ref()
        cur = await db.execute("SELECT 1 FROM projects WHERE token=?", (token,))
        return (await cur.fetchone()) is not None

    # -- ingest / dedup ---------------------------------------------------
    async def ingest_finding(self, p: dict[str, Any]) -> dict[str, Any]:
        db = self._db_ref()
        sh = p["semantic_hash"]
        loc = p.get("location") or {}
        evidence = p.get("evidence") or {}
        cur = await db.execute("SELECT * FROM issues WHERE semantic_hash=?", (sh,))
        existing = await cur.fetchone()
        source_tool = p.get("source_tool") or "unknown"

        if existing:
            row = dict(existing)
            tools = json.loads(row.get("source_tools") or "[]")
            if source_tool not in tools:
                tools.append(source_tool)
            new_status = row["status"]
            reopened = False
            if row["status"] in ("fixed", "wontfix", "false_positive"):
                new_status = "open"
                reopened = True
            await db.execute(
                "UPDATE issues SET status=?, source_tools=?, detection_count=detection_count+1, "
                "last_seen=?, last_review_id=?, ai_closed=0, ai_close_reason=NULL WHERE semantic_hash=?",
                (new_status, json.dumps(tools), _now(), p.get("review_id"), sh),
            )
            await self._event(sh, "re_detected" if not reopened else "reopened",
                              f"re-reported by {source_tool}", {"source_tool": source_tool}, source_tool)
            await db.commit()
            return {"issue_id": sh, "semantic_hash": sh, "status": new_status, "created": False}

        now = _now()
        await db.execute(
            "INSERT INTO issues(semantic_hash, project, repo, category, severity, title, description, "
            "evidence, file, line, function, cwe, owasp, status, source_tools, detection_count, "
            "first_seen, last_seen, last_review_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sh, p.get("project"), p.get("repo"), p.get("category"), p.get("severity"), p.get("title"),
             p.get("description"), json.dumps(evidence), loc.get("file"), loc.get("line"), loc.get("function"),
             p.get("cwe"), p.get("owasp"), "open", json.dumps([source_tool]), 1, now, now, p.get("review_id")),
        )
        await self._event(sh, "created", f"reported by {source_tool}", {"source_tool": source_tool}, source_tool)
        await db.commit()
        return {"issue_id": sh, "semantic_hash": sh, "status": "open", "created": True}

    # -- lifecycle --------------------------------------------------------
    async def update_status(self, sh: str, status: str, comment: str | None,
                            source_tool: str = "manual") -> dict[str, Any] | None:
        from cluescan.models import IssueStatus, can_transition
        db = self._db_ref()
        cur = await db.execute("SELECT status FROM issues WHERE semantic_hash=?", (sh,))
        row = await cur.fetchone()
        if not row:
            return None
        try:
            target = IssueStatus(status)
        except ValueError:
            return None
        current = IssueStatus(row["status"])
        if not can_transition(current, target):
            return {"issue_id": sh, "status": current.value, "error": f"invalid transition {current.value}->{status}"}
        await db.execute("UPDATE issues SET status=? WHERE semantic_hash=?", (status, sh))
        await self._event(sh, "status_changed", f"{current.value} -> {status}",
                          {"from": current.value, "to": status, "comment": comment}, source_tool)
        await db.commit()
        return {"issue_id": sh, "status": status}

    async def autoclose(self, sh: str, reason: str, source_tool: str = "ai") -> dict[str, Any] | None:
        db = self._db_ref()
        cur = await db.execute("SELECT 1 FROM issues WHERE semantic_hash=?", (sh,))
        if not (await cur.fetchone()):
            return None
        await db.execute(
            "UPDATE issues SET status='fixed', ai_closed=1, ai_close_reason=? WHERE semantic_hash=?",
            (reason, sh),
        )
        await self._event(sh, "auto_closed", reason, {"reason": reason}, source_tool)
        await db.commit()
        return {"issue_id": sh, "status": "fixed", "ai_closed": True}

    async def _event(self, sh: str, event_type: str, message: str | None,
                     details: dict, source_tool: str | None) -> None:
        db = self._db_ref()
        await db.execute(
            "INSERT INTO issue_events(semantic_hash, event_type, message, details, source_tool, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (sh, event_type, message, json.dumps(details), source_tool, _now()),
        )

    # -- queries ----------------------------------------------------------
    async def get_issue(self, sh: str) -> dict[str, Any] | None:
        db = self._db_ref()
        cur = await db.execute("SELECT * FROM issues WHERE semantic_hash=?", (sh,))
        row = await cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["source_tools"] = json.loads(d.get("source_tools") or "[]")
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        d["ai_closed"] = bool(d["ai_closed"])
        return d

    async def events(self, sh: str) -> list[dict[str, Any]]:
        db = self._db_ref()
        cur = await db.execute(
            "SELECT event_type, message, details, source_tool, created_at FROM issue_events "
            "WHERE semantic_hash=? ORDER BY id", (sh,),
        )
        out = []
        for r in await cur.fetchall():
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details") or "{}")
            except json.JSONDecodeError:
                d["details"] = {}
            out.append(d)
        return out

    async def list_issues(self, *, project: str | None = None, status: str | None = None,
                          severity: str | None = None, source_tool: str | None = None,
                          limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        db = self._db_ref()
        sql = "SELECT * FROM issues WHERE 1=1"
        params: list[Any] = []
        for col, val in (("project", project), ("status", status), ("severity", severity)):
            if val:
                sql += f" AND {col}=?"
                params.append(val)
        if source_tool:
            sql += " AND source_tools LIKE ?"
            params.append(f'%"{source_tool}"%')
        sql += " ORDER BY first_seen DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        cur = await db.execute(sql, params)
        rows = []
        for r in await cur.fetchall():
            d = dict(r)
            d["source_tools"] = json.loads(d.get("source_tools") or "[]")
            d["ai_closed"] = bool(d["ai_closed"])
            rows.append(d)
        return rows

    async def dashboard(self) -> dict[str, Any]:
        db = self._db_ref()
        out: dict[str, Any] = {}
        cur = await db.execute("SELECT COUNT(*) AS c FROM issues")
        out["total"] = (await cur.fetchone())["c"]
        cur = await db.execute("SELECT severity, COUNT(*) AS c FROM issues GROUP BY severity")
        out["by_severity"] = {r["severity"]: r["c"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT status, COUNT(*) AS c FROM issues GROUP BY status")
        out["by_status"] = {r["status"]: r["c"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT project, COUNT(*) AS c FROM issues GROUP BY project")
        out["by_project"] = {r["project"]: r["c"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT COUNT(*) AS c FROM issues WHERE ai_closed=1")
        out["ai_closed"] = (await cur.fetchone())["c"]
        return out

    async def trends(self, days: int = 30) -> dict[str, Any]:
        db = self._db_ref()
        cur = await db.execute(
            "SELECT DATE(first_seen) AS d, severity, COUNT(*) AS c FROM issues "
            "WHERE first_seen >= DATE('now', ?) GROUP BY d, severity ORDER BY d",
            (f"-{days} days",),
        )
        data: dict[str, dict[str, Any]] = {}
        for r in await cur.fetchall():
            data.setdefault(r["d"], {"date": r["d"]})[r["severity"]] = r["c"]
        return {"days": days, "data": list(data.values())}
