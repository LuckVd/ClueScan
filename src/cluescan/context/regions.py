"""Turn diff hunks into analysis Regions.

A Region = the function enclosing a changed hunk (the unit we analyze), plus the
exact changed snippet for focus. Added files contribute all their functions.
Overlapping hunks in one function collapse to a single Region.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from cluescan.context.languages import language_for_file
from cluescan.context.parser import CodeParser, FuncInfo
from cluescan.vcs import ChangeInfo, ChangeType, DiffResult

_MAX_FUNC_BODY_CHARS = 6000


@dataclass
class Region:
    file: str                       # repo-relative
    language: str | None
    function_name: str | None
    function_body: str | None
    changed_snippet: str = ""
    entry_point: tuple[bool, str | None] = (False, None)
    touched_lines: list[tuple[int, int]] = field(default_factory=list)


def _is_ignored(path: str, patterns: list[str]) -> bool:
    for p in patterns:
        if p.endswith("/"):
            if (path + "/").startswith(p) or ("/" + p) in ("/" + path):
                return True
        elif fnmatch.fnmatch(path, p):
            return True
    return False


def _trim(body: str | None) -> str | None:
    if body and len(body) > _MAX_FUNC_BODY_CHARS:
        return body[:_MAX_FUNC_BODY_CHARS] + "\n... [truncated]"
    return body


def regions_from_diff(
    diff: DiffResult,
    repo: Path,
    parser: CodeParser,
    ignore_patterns: list[str] | None = None,
) -> list[Region]:
    ignore_patterns = ignore_patterns or []
    regions: list[Region] = []

    for change in diff.reviewed_changes:
        if _is_ignored(change.path, ignore_patterns):
            continue
        spec = language_for_file(change.path)
        if spec is None:
            continue  # unsupported language — skip (not analyzed, not failed)
        full_path = repo / change.path
        functions = parser.functions(str(full_path))
        if not functions:
            # non-code structure (e.g. config) — still analyze changed lines
            regions.append(Region(
                file=change.path, language=spec.name, function_name=None,
                function_body=None, changed_snippet=_snippet(full_path, change),
            ))
            continue

        touched = _touched_functions(change, functions)
        for func in touched:
            snippet = _changed_snippet_for_func(full_path, change, func)
            regions.append(Region(
                file=change.path,
                language=spec.name,
                function_name=func.name,
                function_body=_trim(func.body),
                changed_snippet=snippet,
                entry_point=(False, None),
                touched_lines=[(h.new_start, h.new_end) for h in change.hunks],
            ))

    # attach entry-point info
    from cluescan.context.symbols import detect_entry_point
    for r in regions:
        if r.function_body and r.function_name:
            fi = FuncInfo(r.function_name, 0, 0, r.function_body)
            r.entry_point = detect_entry_point(fi)
    return regions


def _touched_functions(change: ChangeInfo, functions: list[FuncInfo]) -> list[FuncInfo]:
    """Functions overlapping any hunk (or all functions for a new file)."""
    if change.change_type == ChangeType.ADDED and not change.hunks:
        return functions
    if not change.hunks:
        return functions[:1] if functions else []
    out: list[FuncInfo] = []
    for func in functions:
        for h in change.hunks:
            if _overlap(func.start_line, func.end_line, h.new_start, h.new_end):
                if func not in out:
                    out.append(func)
                break
    return out or (functions[:3] if functions else [])


def _overlap(a1: int, a2: int, b1: int, b2: int) -> bool:
    return a1 <= b2 and b1 <= a2


def _snippet(full_path: Path, change: ChangeInfo) -> str:
    if not change.hunks:
        return ""
    start = min(h.new_start for h in change.hunks)
    end = max(h.new_end for h in change.hunks)
    return _read_lines(full_path, start, end)


def _changed_snippet_for_func(full_path: Path, change: ChangeInfo, func: FuncInfo) -> str:
    hunks = [h for h in change.hunks if _overlap(func.start_line, func.end_line, h.new_start, h.new_end)]
    if not hunks:
        return ""
    start = max(func.start_line, min(h.new_start for h in hunks))
    end = min(func.end_line, max(h.new_end for h in hunks))
    return _read_lines(full_path, start, end)


def _read_lines(full_path: Path, start: int, end: int) -> str:
    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, start)
    end = min(len(lines), end)
    if start > len(lines) or end < start:
        return ""
    return "\n".join(f"{i + start:>4} | {ln}" for i, ln in enumerate(lines[start - 1 : end]))
