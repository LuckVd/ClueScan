"""The explorer agent loop — ClueScan's heart.

Given a changed Region, the configured LLM autonomously explores the repo to
build a MINIMAL NECESSARY evidence set (does this changed code contain a real,
exploitable vulnerability?). Exploration happens entirely inside ClueScan's own
process/LLM — never in the calling agent's context window.

Model-agnostic: instead of relying on native tool-calling (not all
OpenAI-compatible endpoints support it), we use a strict JSON action protocol.
Each turn the LLM emits exactly one action; we execute it locally and feed back
an observation, until it signals `done` or the step/token budget is hit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cluescan.context.parser import CodeParser
from cluescan.context.regions import Region
from cluescan.context.symbols import (
    extract_callees,
    find_callers,
    grep_symbol,
)
from cluescan.llm import LLMClient, LLMError, TokenUsage, extract_json

SYSTEM_PROMPT = """You are a senior security engineer doing precise, evidence-driven triage.
You are given code that just changed (a git diff region). Your job: gather the
MINIMUM evidence needed to decide whether this change introduces a REAL,
EXPLOITABLE vulnerability — a security bug, a business-logic flaw, or a serious
fragility. You are NOT checking code style, formatting, or minor quality issues.

You have these tools. Each turn you MUST output exactly ONE JSON object (no
prose, no markdown fences) choosing one action:

  {"action": "read_function", "name": "<fn>", "file": "<optional repo-relative path>"}
  {"action": "find_callers", "symbol": "<name>"}            # who calls this?
  {"action": "find_callees", "name": "<fn>", "file": "<path>"}   # what it calls
  {"action": "read_lines", "file": "<path>", "start": <int>, "end": <int>}
  {"action": "grep_symbol", "pattern": "<regex>"}           # locate sinks/sources/sanitizers
  {"action": "done", "evidence_summary": "<2-6 sentences: what you proved, key data flow source->sink, whether user-controlled input reaches a dangerous sink, sanitization status>"}

Rules:
- Prefer SILENCE and few steps. Read only what you need to confirm or refute a
  concrete hypothesis. Do not explore the whole codebase.
- Always confirm: is the tainted input actually user-controlled (trace a
  caller / entry point)? Is there a sanitizer between source and sink?
- When you have enough to decide, immediately call "done".
- If the change is clearly benign, call "done" with evidence_summary explaining why.
"""

MAX_OBS_CHARS = 2500


@dataclass
class Step:
    action: str
    args: dict
    observation: str


@dataclass
class ExplorationResult:
    region: Region
    steps: int = 0
    steps_log: list[Step] = field(default_factory=list)
    evidence_summary: str = ""
    entry_point: tuple[bool, str | None] = (False, None)
    usage: TokenUsage = field(default_factory=TokenUsage)
    error: str | None = None

    def digest(self) -> str:
        """Compact evidence context to hand to the analyzer."""
        parts: list[str] = []
        r = self.region
        ep = self.entry_point
        header = f"# Changed function: {r.function_name or '(top-level)'}  [{r.language}]  file={r.file}"
        if ep[0]:
            header += f"  (ENTRY POINT: {ep[1]})"
        parts.append(header)
        if r.changed_snippet:
            parts.append("## Changed lines\n" + r.changed_snippet)
        if r.function_body:
            parts.append("## Full function\n" + r.function_body)
        # include the bodies the explorer deliberately pulled in
        for s in self.steps_log:
            if s.action == "read_function" and len(s.observation) < 4000:
                parts.append(f"## (explored) {s.action} {s.args}\n{s.observation}")
            elif s.action in ("find_callers", "grep_symbol") and s.observation.strip():
                parts.append(f"## (explored) {s.action} {s.args}\n{s.observation[:1200]}")
        if self.evidence_summary:
            parts.append("## Explorer verdict\n" + self.evidence_summary)
        return "\n\n".join(parts)


class Explorer:
    def __init__(self, parser: CodeParser, repo: Path, llm: LLMClient, *,
                 max_steps: int = 12, char_budget: int = 48000):
        self.parser = parser
        self.repo = repo
        self.llm = llm
        self.max_steps = max_steps
        self.char_budget = char_budget

    async def explore(self, region: Region) -> ExplorationResult:
        result = ExplorationResult(region=region, entry_point=region.entry_point)
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._seed(region)},
        ]
        spent_chars = sum(len(m["content"]) for m in messages)

        for step in range(self.max_steps):
            try:
                resp = await self.llm.complete(messages, temperature=0.0)
            except LLMError as e:
                result.error = f"LLM error during exploration: {e}"
                break
            result.usage.add(resp.usage)
            action = await self._parse_action(resp.content)
            if action is None:
                messages.append({"role": "assistant", "content": resp.content})
                messages.append({"role": "user", "content":
                    "ERROR: respond with exactly one JSON action object per turn."})
                result.steps += 1
                continue

            messages.append({"role": "assistant", "content": json.dumps(action)})
            result.steps += 1

            if action.get("action") == "done":
                result.evidence_summary = str(action.get("evidence_summary", "")).strip()
                break

            obs = await self._execute(action, region)
            result.steps_log.append(Step(
                action=str(action.get("action")),
                args={k: v for k, v in action.items() if k != "action"},
                observation=obs,
            ))
            obs_text = f"OBSERVATION:\n{obs}"
            messages.append({"role": "user", "content": obs_text})
            spent_chars += len(obs_text)
            if spent_chars > self.char_budget:
                messages.append({"role": "user", "content":
                    "BUDGET REACHED: stop exploring and call {\"action\":\"done\", ...} now."})
        else:
            if not result.evidence_summary:
                result.evidence_summary = "Exploration stopped at step budget before explicit completion."

        return result

    # -- seed / parsing ---------------------------------------------------
    @staticmethod
    def _seed(region: Region) -> str:
        lines = [
            f"A change was made in `{region.file}`. Investigate whether it is a real "
            f"exploitable vulnerability (or business-logic flaw / fragility). "
            f"Language: {region.language}.",
        ]
        if region.changed_snippet:
            lines.append("### Changed lines\n" + region.changed_snippet)
        if region.function_body:
            lines.append(f"### Enclosing function `{region.function_name}`\n" + region.function_body)
        lines.append('Begin. Output one JSON action. When sure, call {"action":"done",...}.')
        return "\n\n".join(lines)

    @staticmethod
    async def _parse_action(content: str) -> dict | None:
        try:
            data = await extract_json(content)
        except LLMError:
            return None
        if isinstance(data, dict) and "action" in data:
            return data
        return None

    # -- tool execution ---------------------------------------------------
    async def _execute(self, action: dict, region: Region) -> str:
        name = action.get("action")
        try:
            if name == "read_function":
                return await self._tool_read_function(action, region)
            if name == "find_callers":
                return await self._tool_find_callers(action)
            if name == "find_callees":
                return await self._tool_find_callees(action, region)
            if name == "read_lines":
                return self._tool_read_lines(action)
            if name == "grep_symbol":
                return await self._tool_grep(action)
            return f"unknown action: {name}"
        except Exception as e:  # never let a tool crash the loop
            return f"tool error: {e}"

    async def _tool_read_function(self, action: dict, region: Region) -> str:
        fn = str(action.get("name", "")).strip()
        file_hint = action.get("file")
        primary = str(self.repo / region.file) if not file_hint else str(self.repo / str(file_hint))
        func = await self._locate(fn, primary, file_hint is None)
        if not func:
            return f"function '{fn}' not found"
        loc = str(file_hint or region.file)
        return f"# {func.name} @ {loc}:{func.start_line}-{func.end_line}\n{func.body}"

    async def _locate(self, name: str, primary_file: str, search_repo: bool):
        func = self.parser.function_by_name(primary_file, name)
        if func:
            return func
        if not search_repo:
            return None
        pat = rf"\b(def|func|function|public|private|static)\s+{name}\b|\b{name}\s*\("
        hits = await grep_symbol(self.repo, pat, limit=6)
        for h in hits:
            cand = self.parser.function_by_name(str(self.repo / h.file), name)
            if cand:
                return cand
        return None

    async def _tool_find_callers(self, action: dict) -> str:
        sym = str(action.get("symbol", "")).strip()
        hits = await find_callers(self.repo, sym, limit=20)
        if not hits:
            return f"no callers/references found for '{sym}'"
        return "\n".join(f"{h.file}:{h.line}: {h.snippet}" for h in hits)

    async def _tool_find_callees(self, action: dict, region: Region) -> str:
        fn = str(action.get("name", "")).strip()
        file_hint = action.get("file", region.file)
        func = self.parser.function_by_name(str(self.repo / str(file_hint)), fn)
        if not func:
            return f"function '{fn}' not found in {file_hint}"
        callees = extract_callees(func)
        return f"callees of {fn}: {', '.join(callees) if callees else '(none)'}"

    def _tool_read_lines(self, action: dict) -> str:
        file = str(action.get("file", "")).strip()
        start = int(action.get("start", 1))
        end = int(action.get("end", start))
        return (self.parser.line_range(str(self.repo / file), start, end)
                or f"no content in {file}:{start}-{end}")

    async def _tool_grep(self, action: dict) -> str:
        pat = str(action.get("pattern", "")).strip()
        hits = await grep_symbol(self.repo, pat, limit=20)
        if not hits:
            return f"no matches for /{pat}/"
        return "\n".join(f"{h.file}:{h.line}: {h.snippet}" for h in hits)
