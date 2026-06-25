"""Review Center FastAPI app — the middle-platform backend.

Serves the REST API the local MCP cores sync into (ingest/autoclose/status),
the query/stats endpoints the dashboard uses, and the single-page web UI.
Auth is intentionally light for Phase 1 (small team, localhost): GETs are open;
writes require either the global token or a per-project token issued at
registration. Swapping in real auth later only touches `require_write`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from cluescan.config import Config
from cluescan.review_center.store import CenterStore

_WEB_DIR = Path(__file__).resolve().parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg: Config = app.state.cfg
    store = CenterStore(cfg.storage.center_db)
    await store.connect()
    app.state.store = store
    try:
        yield
    finally:
        await store.close()


async def require_write(request: Request, authorization: str | None = Header(default=None)) -> None:
    """Phase-1 auth: accept the global token or any project token. Open while
    no projects exist yet (bootstrap)."""
    cfg: Config = request.app.state.cfg
    store: CenterStore = request.app.state.store
    token = (authorization or "").removeprefix("Bearer ").strip()
    gtoken = cfg.review_center.auth_token
    if gtoken and token == gtoken:
        return
    if await store.is_valid_token(token):
        return
    if not gtoken and not await store.list_projects():
        return
    raise HTTPException(status_code=401, detail="invalid or missing token")


class ProjectIn(BaseModel):
    name: str
    repo: str | None = None


class StatusIn(BaseModel):
    status: str
    comment: str | None = None
    source_tool: str | None = None


class ReasonIn(BaseModel):
    reason: str
    project: str | None = None
    repo: str | None = None


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="ClueScan Review Center", version="0.1.0", lifespan=lifespan)
    app.state.cfg = cfg
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )
    store_holder: dict[str, CenterStore] = {}

    @app.post("/api/v1/projects")
    async def create_project(body: ProjectIn):
        return await app.state.store.create_project(body.name, body.repo or "")

    @app.post("/api/v1/ingest", dependencies=[Depends(require_write)])
    async def ingest(body: dict):
        return await app.state.store.ingest_finding(body)

    @app.get("/api/v1/issues")
    async def list_issues(
        project: str | None = Query(None), status: str | None = Query(None),
        severity: str | None = Query(None), source_tool: str | None = Query(None),
        limit: int = Query(200, le=1000), offset: int = Query(0, ge=0),
    ):
        return await app.state.store.list_issues(
            project=project, status=status, severity=severity, source_tool=source_tool,
            limit=limit, offset=offset,
        )

    @app.get("/api/v1/issues/{semantic_hash}")
    async def get_issue(semantic_hash: str):
        issue = await app.state.store.get_issue(semantic_hash)
        if not issue:
            raise HTTPException(404, "issue not found")
        return issue

    @app.get("/api/v1/issues/{semantic_hash}/events")
    async def issue_events(semantic_hash: str):
        return await app.state.store.events(semantic_hash)

    @app.patch("/api/v1/issues/{semantic_hash}/status", dependencies=[Depends(require_write)])
    async def update_status(semantic_hash: str, body: StatusIn):
        res = await app.state.store.update_status(
            semantic_hash, body.status, body.comment, body.source_tool or "manual"
        )
        if res is None:
            raise HTTPException(404, "issue not found")
        return res

    @app.post("/api/v1/issues/{semantic_hash}/autoclose", dependencies=[Depends(require_write)])
    async def autoclose(semantic_hash: str, body: ReasonIn):
        res = await app.state.store.autoclose(semantic_hash, body.reason)
        if res is None:
            raise HTTPException(404, "issue not found")
        return res

    @app.get("/api/v1/projects")
    async def list_projects():
        return await app.state.store.list_projects()

    @app.get("/api/v1/stats/dashboard")
    async def dashboard():
        return await app.state.store.dashboard()

    @app.get("/api/v1/stats/trends")
    async def trends(days: int = Query(30, ge=1, le=365)):
        return await app.state.store.trends(days)

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    @app.get("/")
    async def index():
        index_html = _WEB_DIR / "index.html"
        if index_html.exists():
            return FileResponse(index_html)
        return JSONResponse({"name": "ClueScan Review Center", "ui": "not installed"})

    return app


def run_server(cfg: Config) -> None:
    import uvicorn

    uvicorn.run(create_app(cfg), host=cfg.review_center.host, port=cfg.review_center.port, log_level="info")
