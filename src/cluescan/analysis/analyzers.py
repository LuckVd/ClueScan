"""Security + business-logic analyzers.

Each analyzer takes an ExplorationResult (the minimal-evidence digest) and asks
the configured LLM for findings under a strict JSON contract. Output is then
verified against the real repo (anti-hallucination) and filtered by severity.
"""

from __future__ import annotations

from pathlib import Path

from cluescan.analysis import verifier
from cluescan.analysis.prompts import logic_prompts, security_prompts
from cluescan.context.explorer import ExplorationResult
from cluescan.llm import LLMClient, LLMError, extract_json
from cluescan.models import CodeLocation, Finding, Severity, parse_severity, severity_at_least

LOGIC_CONFIDENCE_CAP = 0.7


def _coerce_line(value, default: int = 1) -> int:
    try:
        n = int(value)
        return n if n >= 1 else default
    except (TypeError, ValueError):
        return default


def _to_finding(raw: dict, source: str, source_tool: str, fallback_loc: CodeLocation) -> Finding | None:
    try:
        sev = parse_severity(raw.get("severity", "info"))
    except Exception:
        sev = Severity.INFO
    conf = raw.get("confidence", 0.6)
    try:
        conf = max(0.0, min(float(conf), 1.0))
    except (TypeError, ValueError):
        conf = 0.6
    if source == "logic":
        conf = min(conf, LOGIC_CONFIDENCE_CAP)

    file = str(raw.get("file") or fallback_loc.file)
    line = _coerce_line(raw.get("line"), fallback_loc.line)
    end_line = raw.get("end_line")
    try:
        end_line = int(end_line) if end_line else None
    except (TypeError, ValueError):
        end_line = None
    function = raw.get("function") or fallback_loc.function

    title = str(raw.get("title") or "").strip()
    description = str(raw.get("description") or "").strip()
    if not title or not description:
        return None

    evidence: dict = {}
    for k in ("source", "sink", "data_flow"):
        if raw.get(k):
            evidence[k] = raw[k]

    return Finding(
        category=str(raw.get("category") or source),
        severity=sev,
        confidence=conf,
        title=title[:200],
        description=description,
        fix_suggestion=(str(raw["fix_suggestion"]).strip() if raw.get("fix_suggestion") else None) or None,
        location=CodeLocation(file=file, line=line, end_line=end_line, function=function),
        cwe=str(raw["cwe"]) if raw.get("cwe") else None,
        owasp=str(raw["owasp"]) if raw.get("owasp") else None,
        source=source,
        source_tool=source_tool,
        evidence=evidence,
        missing_check=(str(raw["missing_check"]).strip() if raw.get("missing_check") else None) or None,
        entry_point=(str(raw["entry_point"]).strip() if raw.get("entry_point") else None) or None,
        attack_path=(str(raw["attack_path"]).strip() if raw.get("attack_path") else None) or None,
    )


async def _run_analyzer(llm: LLMClient, system: str, user: str, source: str,
                         source_tool: str, fallback_loc: CodeLocation,
                         require_logic_evidence: bool) -> list[Finding]:
    try:
        resp = await llm.complete(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            json_mode=True,
            temperature=0.0,
        )
    except LLMError:
        return []
    try:
        data = await extract_json(resp.content)
    except LLMError:
        return []
    raw_findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(raw_findings, list):
        return []

    out: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        if require_logic_evidence:
            if not (raw.get("missing_check") and raw.get("entry_point") and raw.get("attack_path")):
                continue  # hard-evidence contract: drop incomplete
        f = _to_finding(raw, source, source_tool, fallback_loc)
        if f:
            out.append(f)
    return out


async def analyze_region(
    exploration: ExplorationResult,
    llm: LLMClient,
    repo: Path,
    *,
    enable_security: bool = True,
    enable_logic: bool = True,
    min_severity: Severity = Severity.LOW,
    source_tool: str = "claude_code",
) -> list[Finding]:
    region = exploration.region
    fallback_loc = CodeLocation(
        file=region.file,
        line=region.touched_lines[0][0] if region.touched_lines else 1,
        function=region.function_name,
    )
    digest = exploration.digest()

    findings: list[Finding] = []
    if enable_security:
        sys_p, usr_p = security_prompts(digest)
        findings += await _run_analyzer(
            llm, sys_p, usr_p, "security", source_tool, fallback_loc, require_logic_evidence=False
        )
    if enable_logic:
        sys_p, usr_p = logic_prompts(digest)
        findings += await _run_analyzer(
            llm, sys_p, usr_p, "logic", source_tool, fallback_loc, require_logic_evidence=True
        )

    # anti-hallucination + severity gate
    verified: list[Finding] = []
    for f in findings:
        v = verifier.verify(repo, f.location.file, f.location.line, f.location.function)
        if not v.ok:
            continue
        if v.downgrade:
            # function mismatch: lower severity one notch
            from cluescan.models import SEVERITY_RANK
            bumped = SEVERITY_RANK[f.severity] + 1
            for sev, rank in SEVERITY_RANK.items():
                if rank == bumped:
                    f = f.model_copy(update={"severity": sev, "confidence": min(f.confidence, 0.5)})
                    break
        if severity_at_least(f.severity, min_severity):
            verified.append(f)
    return verified
