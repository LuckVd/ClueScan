"""Semantic hashing for cross-source issue deduplication.

The hash captures the *essence* of a vulnerability — category + normalized
file/function + sink + source + data flow — and deliberately EXCLUDES line
numbers, description wording, and absolute paths. Two findings with the same
hash are the same issue, even if reported by different AI tools (Cursor vs
Claude Code) or phrased differently. This is the cross-source dedup key shared
by the local core and the Review Center.
"""

from __future__ import annotations

import hashlib
import re


def normalize_text(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip()
    text = re.sub(r"\s+", " ", text)
    text = text.replace("\\", "/")
    # anonymize interpolated variables: $VAR, ${VAR}, {{VAR}} -> $X
    text = re.sub(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", "$X", text)
    text = re.sub(r"\{\{[A-Za-z_][A-Za-z0-9_]*\}\}", "{{X}}", text)
    # anonymize string literals
    text = re.sub(r"'[^']*'", "'X'", text)
    text = re.sub(r'"[^"]*"', '"X"', text)
    return text.lower()


def normalize_file(path: str | None) -> str:
    if not path:
        return ""
    return str(path).strip().replace("\\", "/").lower()


def normalize_function(name: str | None) -> str:
    if not name:
        return ""
    text = str(name).strip().lower()
    for prefix in ("self.", "this.", "cls."):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text


def semantic_hash(finding) -> str:
    """Stable 16-hex hash of a Finding-like object's vulnerability essence."""
    evidence = getattr(finding, "evidence", {}) or {}
    loc = getattr(finding, "location", None)
    parts = [
        normalize_text(getattr(finding, "category", "")),
        normalize_file(getattr(loc, "file", None)),
        normalize_function(getattr(loc, "function", None)),
        normalize_text(evidence.get("sink") or ""),
        normalize_text(evidence.get("source") or ""),
        normalize_text(evidence.get("data_flow") or ""),
    ]
    # business-logic findings (no sink/source) fold in missing_check + attack_path
    if not evidence.get("sink"):
        parts.append(normalize_text(getattr(finding, "missing_check", None)))
        parts.append(normalize_text(getattr(finding, "attack_path", None)))
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"cs_{digest}"


def attach_hash(finding) -> object:
    """Set finding.semantic_hash in place and return it."""
    finding.semantic_hash = semantic_hash(finding)
    return finding
