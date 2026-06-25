"""Language registry: file extension → tree-sitter grammar + function node types.

Grammars are loaded lazily and only for languages whose tree-sitter package is
installed. The set is pluggable — adding a language means adding one entry and
installing its grammar package.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass


@dataclass(frozen=True)
class LanguageSpec:
    name: str
    grammar_pkg: str
    extensions: tuple[str, ...]
    function_nodes: tuple[str, ...]
    # node types that hold a route/handler/entry annotation we treat as entry points
    decorator_nodes: tuple[str, ...] = ()


# Order matters only for display. TypeScript grammar isn't installed in this
# env, so .ts/.tsx fall back to the JavaScript grammar (good-enough function
# extraction; TS-only syntax may occasionally mis-parse).
SPECS: list[LanguageSpec] = [
    LanguageSpec("python", "tree_sitter_python", (".py",),
                 ("function_definition",), ("decorator",)),
    LanguageSpec("javascript", "tree_sitter_javascript",
                 (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
                 ("function_declaration", "method_definition",
                  "generator_function_declaration", "class_declaration"),
                 ("decorator",)),
    LanguageSpec("java", "tree_sitter_java", (".java",),
                 ("method_declaration", "constructor_declaration", "class_declaration"),
                 ("marker_annotation", "annotation")),
    LanguageSpec("go", "tree_sitter_go", (".go",),
                 ("function_declaration", "method_declaration")),
]

_BY_EXT: dict[str, LanguageSpec] = {}
for _spec in SPECS:
    for _ext in _spec.extensions:
        _BY_EXT[_ext] = _spec


def language_for_file(path: str) -> LanguageSpec | None:
    lower = path.lower()
    for ext, spec in _BY_EXT.items():
        if lower.endswith(ext):
            return spec
    return None


def supported_languages() -> list[str]:
    """Names of languages whose grammar actually imports successfully."""
    out = []
    for spec in SPECS:
        try:
            importlib.import_module(spec.grammar_pkg)
            out.append(spec.name)
        except Exception:
            continue
    return out
