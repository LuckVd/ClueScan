"""Tree-sitter code parser.

Extracts structural facts a security explorer needs, without a heavy CPG/AST
graph subsystem:
  * list functions (name, line span, body)
  * find the function enclosing a given line (for diff hunk → region expansion)
  * fetch a named function's body
  * fetch an arbitrary line range

Uses the new tree-sitter Python API (Language(pkg.language()) + Parser(language))
and walks the AST by node type — stable across tree-sitter versions.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Language, Parser

from cluescan.context.languages import LanguageSpec, language_for_file


@dataclass
class FuncInfo:
    name: str
    start_line: int          # 1-based, inclusive
    end_line: int            # 1-based, inclusive
    body: str


class CodeParser:
    """Parses a single source file on demand; caches its tree per content."""

    def __init__(self):
        self._parsers: dict[str, Parser] = {}

    # -- grammar / parser cache ------------------------------------------
    def _parser_for(self, spec: LanguageSpec) -> Parser:
        if spec.name not in self._parsers:
            mod = importlib.import_module(spec.grammar_pkg)
            language = Language(mod.language())
            self._parsers[spec.name] = Parser(language)
        return self._parsers[spec.name]

    def _parse(self, spec: LanguageSpec, source: str):
        return self._parser_for(spec).parse(bytes(source, "utf-8"))

    # -- public API -------------------------------------------------------
    def functions(self, file_path: str, source: str | None = None) -> list[FuncInfo]:
        spec = language_for_file(file_path)
        if spec is None:
            return []
        src = source if source is not None else _read(file_path)
        tree = self._parse(spec, src)
        out: list[FuncInfo] = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in spec.function_nodes:
                info = self._func_info(node, src)
                if info:
                    out.append(info)
            for child in node.children:
                stack.append(child)
        out.sort(key=lambda f: f.start_line)
        return out

    def enclosing_function(self, file_path: str, line: int, source: str | None = None) -> FuncInfo | None:
        """Smallest function whose span contains `line` (1-based)."""
        best: FuncInfo | None = None
        for f in self.functions(file_path, source):
            if f.start_line <= line <= f.end_line:
                if best is None or f.end_line < best.end_line:
                    best = f
        return best

    def function_by_name(self, file_path: str, name: str, source: str | None = None) -> FuncInfo | None:
        for f in self.functions(file_path, source):
            if f.name == name:
                return f
        return None

    def line_range(self, file_path: str, start: int, end: int) -> str:
        src = _read(file_path)
        lines = src.splitlines()
        start = max(1, start)
        end = min(len(lines), end)
        if start > len(lines):
            return ""
        chunk = lines[start - 1 : end]
        return "\n".join(f"{i + start:>4} | {ln}" for i, ln in enumerate(chunk))

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _func_info(node, src: str) -> FuncInfo | None:
        name_node = node.child_by_field_name("name")
        name = ""
        if name_node is not None:
            name = name_node.text.decode("utf-8", "replace")
        else:
            # fall back: first identifier-like child
            for ch in node.children:
                if ch.type in ("identifier", "property_identifier"):
                    name = ch.text.decode("utf-8", "replace")
                    break
        if not name:
            return None
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        body = node.text.decode("utf-8", "replace")
        return FuncInfo(name=name, start_line=start_line, end_line=end_line, body=body)


def _read(file_path: str) -> str:
    try:
        return Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
