"""Domain models shared across the local MCP core and the Review Center.

  * Finding  — transient output of an analyzer (security / logic), pre-dedup.
  * Issue    — persisted record (canonical at the center, mirrored in local cache).
  * IssueEvent — lifecycle audit trail entry.

`semantic_hash` is the cross-source dedup key (see cluescan.dedup.semantic).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_at_least(s: Severity, minimum: Severity) -> bool:
    return SEVERITY_RANK[s] <= SEVERITY_RANK[minimum]


def parse_severity(value: str | Severity) -> Severity:
    v = value.lower() if isinstance(value, str) else value.value
    try:
        return Severity(v)
    except ValueError:
        return Severity.INFO


class IssueStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FIXING = "fixing"
    FIXED = "fixed"
    WONTFIX = "wontfix"
    FALSE_POSITIVE = "false_positive"


# Allowed transitions (source_status -> set of target statuses).
STATUS_TRANSITIONS: dict[IssueStatus, set[IssueStatus]] = {
    IssueStatus.OPEN: {IssueStatus.CONFIRMED, IssueStatus.FIXING, IssueStatus.FIXED,
                       IssueStatus.WONTFIX, IssueStatus.FALSE_POSITIVE},
    IssueStatus.CONFIRMED: {IssueStatus.FIXING, IssueStatus.FIXED, IssueStatus.WONTFIX,
                            IssueStatus.FALSE_POSITIVE, IssueStatus.OPEN},
    IssueStatus.FIXING: {IssueStatus.FIXED, IssueStatus.WONTFIX, IssueStatus.OPEN,
                         IssueStatus.FALSE_POSITIVE},
    IssueStatus.FIXED: {IssueStatus.OPEN},  # reopen on re-surface
    IssueStatus.WONTFIX: {IssueStatus.OPEN, IssueStatus.CONFIRMED},
    IssueStatus.FALSE_POSITIVE: {IssueStatus.OPEN, IssueStatus.CONFIRMED},
}


def can_transition(a: IssueStatus, b: IssueStatus) -> bool:
    return a == b or b in STATUS_TRANSITIONS.get(a, set())


class CodeLocation(BaseModel):
    file: str
    line: int = Field(ge=1)
    end_line: int | None = None
    function: str | None = None
    snippet: str | None = None

    def display(self) -> str:
        loc = f"{self.file}:{self.line}"
        if self.end_line and self.end_line != self.line:
            loc += f"-{self.end_line}"
        return loc


class Finding(BaseModel):
    """Transient analyzer output. Carries everything needed to compute a
    semantic hash and to create/update an Issue."""

    category: str                       # e.g. "sql_injection", "missing_authz"
    severity: Severity
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    title: str
    description: str
    fix_suggestion: str | None = None
    location: CodeLocation
    cwe: str | None = None
    owasp: str | None = None

    # Analyzer provenance
    source: str = "security"            # "security" | "logic"
    source_tool: str = "claude_code"    # claude_code | cursor | codex | zed | manual | ...

    # Minimal-evidence payload gathered by the explorer
    evidence: dict[str, Any] = Field(default_factory=dict)

    # Business-logic hard-evidence contract (logic analyzer requires all three)
    missing_check: str | None = None
    entry_point: str | None = None
    attack_path: str | None = None

    # Computed by dedup.semantic
    semantic_hash: str | None = None


class Issue(BaseModel):
    """Canonical record owned by the Review Center; mirrored in local cache."""

    id: str
    project: str                        # repo identifier registered with the center
    semantic_hash: str
    category: str
    severity: Severity
    title: str
    description: str
    location: CodeLocation
    status: IssueStatus = IssueStatus.OPEN
    cwe: str | None = None
    owasp: str | None = None
    fix_suggestion: str | None = None

    source_tools: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)

    # Auto-close
    ai_closed: bool = False
    ai_close_reason: str | None = None

    # Lifecycle counters / timestamps
    open_count: int = 1
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    last_review_id: str | None = None

    def to_finding(self) -> Finding:
        """Project back to a Finding shape (used by local cache consumers)."""
        return Finding(
            category=self.category,
            severity=self.severity,
            title=self.title,
            description=self.description,
            fix_suggestion=self.fix_suggestion,
            location=self.location,
            cwe=self.cwe,
            owasp=self.owasp,
            source="security",
            source_tool=self.source_tools[0] if self.source_tools else "unknown",
            evidence=self.evidence,
            semantic_hash=self.semantic_hash,
        )


class IssueEvent(BaseModel):
    issue_id: str
    event_type: str                     # created|reopened|status_changed|auto_closed|...
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    source_tool: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class ReviewResult(BaseModel):
    """What a review produces locally — a brief summary for the agent + the
    full finding list (which also gets persisted / synced)."""

    review_id: str
    repo: str
    base_ref: str
    head_ref: str
    files_reviewed: int = 0
    findings: list[Finding] = Field(default_factory=list)
    new_issues: int = 0
    merged_issues: int = 0
    auto_closed: int = 0
    skipped_duplicate: bool = False
    region_errors: int = 0
    duration_seconds: float = 0.0
    center_url: str | None = None
    error: str | None = None

    def summary(self, max_items: int = 5) -> str:
        """Concise, low-context summary returned to the calling agent.

        Never reports a silent 'clean' when regions failed analysis — that would
        mask LLM timeouts as false negatives."""
        if self.error:
            return f"ClueScan review failed: {self.error}"
        if not self.findings:
            if self.region_errors:
                return (
                    f"ClueScan: review INCOMPLETE — {self.region_errors} region(s) failed "
                    f"analysis (e.g. LLM timeout/error). No issues confirmed; please re-run. "
                    f"(reviewed {self.files_reviewed} file(s))"
                )
            return (
                f"ClueScan: clean. Reviewed {self.files_reviewed} changed file(s); "
                f"no security/business-logic issues found."
            )
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        parts = [f"{c} {s}" for s, c in sorted(by_sev.items(), key=lambda kv: SEVERITY_RANK[Severity(kv[0])])]
        top = sorted(self.findings, key=lambda f: SEVERITY_RANK[f.severity])[:max_items]
        lines = [
            f"ClueScan found {len(self.findings)} issue(s) ({', '.join(parts)}).",
        ]
        for f in top:
            lines.append(f"  - [{f.severity.value.upper()}] {f.title} @ {f.location.display()}")
        if self.auto_closed:
            lines.append(f"  ({self.auto_closed} previously-open issue(s) auto-closed as fixed)")
        if self.region_errors:
            lines.append(
                f"  WARNING: {self.region_errors} region(s) failed analysis (e.g. LLM timeout) — "
                f"results may be incomplete; re-run to be sure."
            )
        if self.center_url:
            lines.append(f"Full details: {self.center_url}")
        return "\n".join(lines)
