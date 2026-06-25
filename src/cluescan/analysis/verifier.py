"""Anti-hallucination verification.

Before a finding becomes an Issue we confirm it points at real code: the file
exists and the line is in range. Findings that fail are dropped; findings whose
reported function name isn't found near the line are downgraded. This is the
main false-positive brake (per the 'real vulns, not hallucination' goal).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Verification:
    ok: bool
    reason: str = ""

    @property
    def downgrade(self) -> bool:
        """Soft mismatch: keep but lower severity."""
        return self.reason == "function_mismatch"


def verify(repo: Path, file: str, line: int, function: str | None) -> Verification:
    full = repo / file
    if not full.exists():
        return Verification(ok=False, reason="file_not_found")
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return Verification(ok=False, reason="unreadable")
    if not (1 <= line <= len(lines)):
        return Verification(ok=False, reason="line_out_of_range")
    if function:
        # function name should appear within +/- 60 lines of the reported line
        window = "\n".join(lines[max(0, line - 61):line + 60]).lower()
        if function.lower() not in window:
            return Verification(ok=True, reason="function_mismatch")
    return Verification(ok=True)
