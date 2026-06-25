"""Git diff as the primary analysis object.

ChangeDetector turns `git diff` into structured ChangeInfo (per-file hunks in
the NEW file), plus a content hash used for trigger dedup. Everything here is
pure `git` plumbing via subprocess — no GitPython dependency.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass
class Hunk:
    """Line range in the NEW version of the file (inclusive)."""
    new_start: int
    new_end: int


@dataclass
class ChangeInfo:
    path: str                       # path in the new tree (relative to repo root)
    change_type: ChangeType
    old_path: str | None = None     # for renames
    additions: int = 0
    deletions: int = 0
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def is_code_added_or_modified(self) -> bool:
        return self.change_type in (ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.RENAMED)


@dataclass
class DiffResult:
    repo: str
    base_ref: str
    head_ref: str                   # "WORKTREE" when diffing against working tree
    changes: list[ChangeInfo] = field(default_factory=list)
    content_hash: str = ""

    @property
    def reviewed_changes(self) -> list[ChangeInfo]:
        return [c for c in self.changes if c.is_code_added_or_modified]

    @property
    def total_additions(self) -> int:
        return sum(c.additions for c in self.changes)

    @property
    def total_deletions(self) -> int:
        return sum(c.deletions for c in self.changes)


class GitError(RuntimeError):
    pass


class ChangeDetector:
    def __init__(self, repo_path: str | Path):
        self.repo = Path(repo_path).resolve()

    # -- low level --------------------------------------------------------
    async def _git(self, *args: str, check: bool = True) -> str:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(self.repo), *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if check and proc.returncode != 0:
            raise GitError(
                f"git {' '.join(args)} failed ({proc.returncode}): {stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace")

    async def is_repo(self) -> bool:
        try:
            await self._git("rev-parse", "--is-inside-work-tree")
            return True
        except GitError:
            return False

    async def head_sha(self) -> str:
        return (await self._git("rev-parse", "HEAD")).strip()

    # -- diff -------------------------------------------------------------
    async def detect(
        self,
        base_ref: str = "HEAD",
        head_ref: str | None = None,
    ) -> DiffResult:
        """Diff `base_ref` against `head_ref` (or the working tree if None).

        head_ref=None → compares base_ref to the working tree (uncommitted +
        staged changes), which is the common 'review what I just wrote' case.
        """
        rev_range = base_ref if head_ref is None else f"{base_ref}..{head_ref}"
        head_label = head_ref if head_ref is not None else "WORKTREE"

        raw = await self._git("diff", "--raw", "--no-renames", "-z", rev_range)
        numstat = await self._git("diff", "--numstat", "-z", rev_range)
        unified = await self._git("diff", "-U0", "--no-color", rev_range)

        changes = self._parse_files(raw, numstat)
        self._attach_hunks(changes, unified)
        content_hash = hashlib.sha256(unified.encode("utf-8")).hexdigest()[:16]

        return DiffResult(
            repo=str(self.repo),
            base_ref=base_ref,
            head_ref=head_label,
            changes=changes,
            content_hash=content_hash,
        )

    # -- parsers ----------------------------------------------------------
    @staticmethod
    def _parse_files(raw: str, numstat: str) -> list[ChangeInfo]:
        # --raw -z: records are colon-prefixed metadata, NUL, path[, NUL, oldpath]
        # --numstat -z: "added\tdeleted\tpath" NUL separated
        changes: dict[str, ChangeInfo] = {}
        order: list[str] = []

        raw_recs = [r for r in raw.split("\0") if r]
        numstat_recs = [r for r in numstat.split("\0") if r]
        numstat_map: dict[str, tuple[int, int]] = {}
        for ns in numstat_recs:
            parts = ns.split("\t")
            if len(parts) >= 3:
                add = 0 if parts[0] == "-" else int(parts[0])
                dele = 0 if parts[1] == "-" else int(parts[1])
                numstat_map[parts[2]] = (add, dele)

        i = 0
        while i < len(raw_recs):
            meta = raw_recs[i]
            if not meta.startswith(":"):
                i += 1
                continue
            # meta = ":100644 100644 sha sha STATUS\tpath"  (with --no-renames status is a single letter)
            try:
                status_field = meta.split("\t", 1)[0].split()[-1]  # last token before \t
            except IndexError:
                i += 1
                continue
            status = status_field[0].upper()
            path1 = raw_recs[i + 1] if i + 1 < len(raw_recs) else ""
            path2 = raw_recs[i + 2] if i + 2 < len(raw_recs) and not raw_recs[i + 2].startswith(":") else None

            if status == "R" and path2 is not None:
                change = ChangeInfo(path=path2, change_type=ChangeType.RENAMED, old_path=path1)
                i += 3
            elif status == "C" and path2 is not None:
                change = ChangeInfo(path=path2, change_type=ChangeType.ADDED, old_path=path1)
                i += 3
            elif status == "A":
                change = ChangeInfo(path=path1, change_type=ChangeType.ADDED)
                i += 2
            elif status == "D":
                change = ChangeInfo(path=path1, change_type=ChangeType.DELETED)
                i += 2
            else:  # M or anything else
                change = ChangeInfo(path=path1, change_type=ChangeType.MODIFIED)
                i += 2

            add, dele = numstat_map.get(change.path, (0, 0))
            change.additions = add
            change.deletions = dele
            if change.path not in changes:
                changes[change.path] = change
                order.append(change.path)
        return [changes[p] for p in order]

    @staticmethod
    def _attach_hunks(changes: list[ChangeInfo], unified: str) -> None:
        by_path = {c.path: c for c in changes}
        current_path: str | None = None
        hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
        for line in unified.splitlines():
            if line.startswith("+++ b/"):
                current_path = line[6:]
            elif line.startswith("@@"):
                m = hunk_re.match(line)
                if not m:
                    continue
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                end = start if count == 0 else start + count - 1
                if current_path and current_path in by_path:
                    by_path[current_path].hunks.append(Hunk(new_start=start, new_end=end))
