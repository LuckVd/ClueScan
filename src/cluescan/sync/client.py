"""Offline-first sync to the Review Center.

The local core never blocks on the center. Findings + autoclose decisions land
in a local outbox; `drain_once` (called by the MCP background task or the
`cluescan sync` CLI) ships them to the center's REST API, retrying with backoff
while the center is unreachable. The center reconciles by semantic hash, so
re-delivery is idempotent.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from cluescan.config import Config
from cluescan.store import LocalStore


class CenterUnavailable(Exception):
    pass


class CenterClient:
    def __init__(self, base_url: str, token: str | None, *, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _post(self, path: str, body: dict) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            try:
                resp = await c.post(f"{self.base_url}{path}", json=body, headers=self._headers())
            except httpx.HTTPError as e:
                raise CenterUnavailable(str(e))
        if resp.status_code >= 500:
            raise CenterUnavailable(f"center {resp.status_code}: {resp.text[:200]}")
        if resp.status_code >= 400:
            # 4xx is a real rejection — don't retry forever; surface it.
            raise CenterUnavailable(f"center rejected ({resp.status_code}): {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            return {}

    async def ingest_finding(self, payload: dict) -> dict:
        return await self._post("/api/v1/ingest", payload)

    async def autoclose(self, payload: dict) -> dict:
        h = payload.get("semantic_hash", "")
        return await self._post(f"/api/v1/issues/{h}/autoclose",
                                {"reason": payload.get("reason"), "project": payload.get("project"),
                                 "repo": payload.get("repo")})

    async def register_project(self, name: str, repo: str) -> dict:
        return await self._post("/api/v1/projects", {"name": name, "repo": repo})


async def drain_once(cfg: Config, *, limit: int = 100) -> int:
    """Ship pending outbox records to the center. Returns count delivered."""
    store = LocalStore(cfg.storage.local_db)
    await store.connect()
    done = 0
    try:
        records = await store.pending(limit)
        if not records:
            return 0
        token = cfg.sync.auth_token or cfg.review_center.auth_token
        client = CenterClient(cfg.sync.endpoint, token)
        for rec in records:
            kind = rec["kind"]
            payload = rec["payload"]
            try:
                if kind == "finding":
                    resp = await client.ingest_finding(payload)
                    # reconcile local cache with the center-assigned issue_id
                    issue_id = resp.get("issue_id") if isinstance(resp, dict) else None
                    if issue_id and payload.get("semantic_hash"):
                        cached = await store.get_issue(payload["semantic_hash"])
                        if cached:
                            cached["issue_id"] = issue_id
                            await store.upsert_issue(cached)
                elif kind == "autoclose":
                    await client.autoclose(payload)
                else:
                    pass
                await store.mark_done(rec["id"])
                done += 1
            except CenterUnavailable:
                attempts = rec["attempts"] + 1
                backoff = min(cfg.sync.retry_backoff * (2 ** min(attempts, 6)), 3600)
                next_retry = (datetime.now(timezone.utc) + timedelta(seconds=backoff)).isoformat()
                await store.schedule_retry(rec["id"], next_retry, attempts)
        return done
    finally:
        await store.close()


async def register_project(cfg: Config, *, repo_path: str, name: str | None,
                           center_url: str | None) -> dict:
    repo = str(Path(repo_path).resolve())
    center_url = center_url or cfg.sync.endpoint
    token = cfg.review_center.auth_token or cfg.sync.auth_token
    client = CenterClient(center_url, token)
    project_name = name or Path(repo).name or "project"
    resp = await client.register_project(project_name, repo)
    project = resp.get("project", project_name)
    reg_token = resp.get("token", token)
    store = LocalStore(cfg.storage.local_db)
    await store.connect()
    try:
        await store.save_registration(repo, project, reg_token, center_url)
    finally:
        await store.close()
    return {"project": project, "token": reg_token, "center_url": center_url}
