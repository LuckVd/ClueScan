"""Symbol discovery via a pure-Python repo index (no ripgrep dependency).

Backs the explorer's `find_callers` / `grep_symbol` tools and the entry-point
detector. A RepoIndex walks the repo once (skipping VCS/build/dep dirs and
binary/huge files), then answers repeated regex/word searches from cache —
fast enough for the explorer loop without shelling out to ripgrep.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Hit:
    file: str               # repo-relative
    line: int
    snippet: str


# Directories never searched (build artifacts, deps, VCS).
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "target", "venv", ".venv", "env",
    "__pycache__", ".next", ".nuxt", ".cache", ".idea", ".vscode", "vendor",
    ".tox", ".eggs", ".mypy_cache", ".pytest_cache", "coverage", ".gradle",
}
# Extensions treated as searchable source/text. Broad enough to catch sinks in
# templates/configs without indexing binaries.
_SEARCH_EXTS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".scala",
    ".go", ".rs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".cs", ".rb",
    ".php", ".swift", ".sh", ".bash", ".sql", ".html", ".htm", ".vue", ".svelte",
    ".yaml", ".yml", ".json", ".toml", ".xml", ".cfg", ".ini", ".env",
}
_MAX_FILE_BYTES = 512 * 1024

# Patterns that mark a function as an external entry point.
_ENTRY_DECORATORS = [
    r"@app\.(route|get|post|put|delete|patch|head)",
    r"@(router|api_router|blueprint)\.(route|get|post|put|delete|patch|head)",
    r"@(get|post|put|delete|patch)Mapping",
    r"@RequestMapping",
    r"@RestController|@Controller",
    r"@api_view|@action\b",
    r"@app\.(command|shell_command)",
    r"@(task|celery_app\.task|shared_task)\b",
    r"@(Scheduled|EnableScheduling)",
]
_ENTRY_DECORATORS_RE = re.compile("|".join(_ENTRY_DECORATORS), re.IGNORECASE)

_CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")


class RepoIndex:
    def __init__(self, repo: Path):
        self.repo = Path(repo)
        self._files: list[tuple[str, Path]] = []  # (relpath, abspath)
        self._built = False

    def _build(self) -> None:
        if self._built:
            return
        repo = self.repo
        for path in repo.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SEARCH_EXTS:
                continue
            # skip if any path component is a skip dir
            try:
                rel = path.relative_to(repo)
            except ValueError:
                continue
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            self._files.append((rel.as_posix(), path))
        self._built = True

    def search(self, pattern: str, *, limit: int = 25, word: bool = False) -> list[Hit]:
        self._build()
        try:
            if word:
                rx = re.compile(r"\b" + re.escape(pattern) + r"\b")
            else:
                rx = re.compile(pattern)
        except re.error:
            rx = re.compile(re.escape(pattern))
        hits: list[Hit] = []
        for rel, abspath in self._files:
            try:
                data = abspath.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:4096]:
                continue  # binary
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if rx.search(line):
                    hits.append(Hit(file=rel, line=i, snippet=line.strip()[:200]))
                    if len(hits) >= limit:
                        return hits
        return hits


_INDEX_CACHE: dict[str, RepoIndex] = {}


def _index_for(repo: Path) -> RepoIndex:
    key = str(Path(repo).resolve())
    idx = _INDEX_CACHE.get(key)
    if idx is None:
        idx = RepoIndex(Path(repo))
        _INDEX_CACHE[key] = idx
    return idx


def clear_index_cache(repo: Path | None = None) -> None:
    if repo is None:
        _INDEX_CACHE.clear()
    else:
        _INDEX_CACHE.pop(str(Path(repo).resolve()), None)


async def find_callers(repo: Path, symbol: str, *, limit: int = 25) -> list[Hit]:
    """Places that reference `symbol` (call sites / imports)."""
    if not symbol or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", symbol):
        return []
    return _index_for(repo).search(symbol, limit=limit, word=True)


async def grep_symbol(repo: Path, pattern: str, *, limit: int = 25) -> list[Hit]:
    """Regex search across the repo."""
    return _index_for(repo).search(pattern, limit=limit, word=False)


def extract_callees(func) -> list[str]:
    """Candidate function calls within a function body (names preceding `(`)."""
    seen: list[str] = []
    seen_set: set[str] = set()
    body = getattr(func, "body", "") or ""
    for name in _CALL_RE.findall(body):
        if name in seen_set or name.startswith(
            ("if", "for", "while", "switch", "return", "print", "elif")
        ):
            continue
        seen_set.add(name)
        seen.append(name)
    return seen


def detect_entry_point(func) -> tuple[bool, str | None]:
    """Returns (is_entry_point, entry_type)."""
    body = getattr(func, "body", "") or ""
    if _ENTRY_DECORATORS_RE.search(body):
        return True, "http"
    lname = (getattr(func, "name", "") or "").lower()
    if lname in ("main",) or lname.startswith(("handle_", "on_", "do_", "serve")):
        return True, "entry"
    if "controller" in lname or "handler" in lname or "endpoint" in lname:
        return True, "handler"
    if "command" in lname:
        return True, "cli"
    return False, None
