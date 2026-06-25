"""Configuration: YAML-first with ${ENV} interpolation and ENV overrides.

Resolution order for a value: explicit ENV override (CLUESCAN_<SECTION>_<KEY>)
  > YAML value (with ${VAR} / ${VAR:-default} interpolation) > model default.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, get_origin

import yaml
from pydantic import BaseModel, Field

_ENV_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
_DEFAULT_CONFIG_NAME = "cluescan.yaml"


class LLMConfig(BaseModel):
    base_url: str = "https://open.bigmodel.cn/api/paas/v4"
    api_key: str = ""
    model: str = "glm-4.6"
    concurrency: int = Field(3, ge=1, le=32)
    max_tokens: int = 16384
    temperature: float = 0.1
    timeout: int = 60
    max_retries: int = 2


class TriggersConfig(BaseModel):
    debounce_ms: int = 2500
    sources: list[str] = Field(default_factory=lambda: ["skill"])


class AnalysisConfig(BaseModel):
    context_token_budget: int = 12000
    explorer_max_steps: int = 12
    enable_security: bool = True
    enable_logic_vuln: bool = True
    min_severity: str = "low"
    region_timeout_seconds: int = 90  # hard cap per changed region; prevents LLM hangs
    languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "java", "go"]
    )


class DedupConfig(BaseModel):
    line_tolerance: int = 10
    enable_llm_judge: bool = False  # Phase 1: rule-based semantic hash only


class AutocloseConfig(BaseModel):
    enabled: bool = True
    reverify_stale_days: int = 7


class StorageConfig(BaseModel):
    local_db: str = "~/.cluescan/local.db"
    center_db: str = "~/.cluescan/center.db"


class ReviewCenterConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8787
    auth_token: str = ""


class SyncConfig(BaseModel):
    endpoint: str = "http://127.0.0.1:8787"
    auth_token: str = ""
    retry_backoff: int = 5
    max_retries: int = 0  # 0 = unbounded


class McpConfig(BaseModel):
    transport: str = "stdio"  # stdio | streamable-http


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    triggers: TriggersConfig = Field(default_factory=TriggersConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    autoclose: AutocloseConfig = Field(default_factory=AutocloseConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    review_center: ReviewCenterConfig = Field(default_factory=ReviewCenterConfig)
    sync: SyncConfig = Field(default_factory=SyncConfig)
    mcp: McpConfig = Field(default_factory=McpConfig)
    ignore_patterns: list[str] = Field(
        default_factory=lambda: ["*.lock", "dist/", "node_modules/", "*.min.js"]
    )

    def expand(self, path: str) -> Path:
        """Expand a user-relative storage path to an absolute Path."""
        return Path(os.path.expanduser(path))


def _interpolate(value: Any) -> Any:
    """Recursively replace ${VAR} / ${VAR:-default} using os.environ."""
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            return os.environ.get(name, default if default is not None else m.group(0))
        return _ENV_VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def _find_config_path(explicit: str | Path | None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None
    env_path = os.environ.get("CLUESCAN_CONFIG")
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p
    for candidate in (Path.cwd() / _DEFAULT_CONFIG_NAME, Path.home() / ".cluescan" / "config.yaml"):
        if candidate.exists():
            return candidate
    return None


def load_config(explicit_path: str | Path | None = None) -> Config:
    """Load configuration from YAML (with env interpolation), then apply
    CLUESCAN_<SECTION>_<KEY> environment overrides, then validate."""
    path = _find_config_path(explicit_path)
    raw: dict[str, Any] = {}
    if path:
        with path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if isinstance(loaded, dict):
            raw = _interpolate(loaded)

    # Environment overrides: CLUESCAN_LLM_MODEL etc.
    for section_name, finfo in Config.model_fields.items():
        section_cls = finfo.annotation
        if get_origin(section_cls) is list or section_cls in (list,):
            continue  # ignore_patterns etc. are plain lists
        section_fields = getattr(section_cls, "model_fields", None)
        if not section_fields:
            continue
        for field_name in section_fields:
            env_key = f"CLUESCAN_{section_name.upper()}_{field_name.upper()}"
            if env_key in os.environ:
                raw.setdefault(section_name, {})[field_name] = os.environ[env_key]

    return Config.model_validate(raw)
