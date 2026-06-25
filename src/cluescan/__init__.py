"""ClueScan — AI-native shift-left security review.

Two-tier architecture:
  * Local MCP Server (execution core) — does code-dependent work: git diff,
    LLM-driven context exploration, security analysis, auto-close re-verification.
  * Review Center (middle platform) — always-on backend that owns the Issue
    lifecycle, cross-source dedup, aggregation, statistics, and the web UI.

ClueScan is fully self-contained and independent of any sibling projects.
"""

__version__ = "0.1.0"
