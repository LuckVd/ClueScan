# ClueScan

**AI-native shift-left security review for the AI-coding era.**

ClueScan is a local MCP (Model Context Protocol) security-review core that any AI
coding agent (Claude Code, Codex, Cursor, Zed) can plug into, plus a Review Center
middle-platform that aggregates findings into a unified Issue lifecycle.

It is **not** another traditional SAST. After an AI finishes a feature (or a dev
writes code), a Skill triggers a review over the **git diff**. ClueScan drives a
**user-configured LLM** to autonomously explore the relevant code context and build a
**minimal necessary evidence set** — all inside its own process, **never consuming the
agent's context window** — and surfaces real **security / business-logic / fragility**
issues (not style). Findings sync to the Review Center, which dedups them across tools
and manages their full lifecycle, including **AI auto-close** when a fix is verified.

## Architecture (two tiers)

```
AI Agent ──/security-review skill──▶ Local MCP Server (execution core)
                                         │ git diff → LLM evidence exploration
                                         │ → security + logic analysis → findings
                                         │ → semantic-hash dedup → local SQLite + outbox
                                         └── async HTTP (offline-first) ──▶ Review Center
                                                                               (FastAPI + web UI)
                                                                               cross-source dedup,
                                                                               lifecycle, auto-close,
                                                                               stats
```

- **Local MCP** does everything that needs source access (analysis, evidence, auto-close re-check).
- **Review Center** is the single source of truth for Issues (cross-tool aggregation, lifecycle, stats, UI).

## Quick start

```bash
pip install -e .                       # or: pip install -e . --break-system-packages

cluescan init                          # writes cluescan.yaml
# edit cluescan.yaml: set llm.api_key (CLUESCAN_LLM_API_KEY) + model/base_url

cluescan serve-web                     # start the Review Center (http://127.0.0.1:8787)
cluescan register .                    # register this repo as a project (saves token)
cluescan install-skill                 # install the /security-review skill
```

Then connect the MCP server to your agent (Claude Code `mcpServers` config):

```json
{ "mcpServers": { "cluescan": { "command": "cluescan", "args": ["serve-mcp"] } } }
```

Ask the agent to implement a feature; it will run `/security-review` when done, or
call the `review_diff` tool directly.

## MCP tools

| tool | purpose |
|---|---|
| `review_diff` | review the current git diff; returns a short summary |
| `review_code` | review an in-memory snippet |
| `auto_close_check` | re-verify open issues; auto-close fixed ones |
| `list_issues` / `get_issue` / `get_summary` | query the local issue mirror |
| `update_issue_status` | change an issue's status |
| `submit_finding` | submit a finding you noticed (cross-tool aggregation) |

## Configuration

See `cluescan.yaml.example`. Any value supports `${ENV}` interpolation and
`CLUESCAN_<SECTION>_<KEY>` env overrides (e.g. `CLUESCAN_LLM_API_KEY`).

The LLM is any OpenAI-compatible endpoint (OpenAI, GLM/Zhipu, Ollama `/v1`, vLLM…).

## Languages

Python, JavaScript/TypeScript, Java, Go (tree-sitter; pluggable). More grammars =
one registry entry + a package install.

## Project layout

```
src/cluescan/
  config/      YAML+ENV configuration
  models/      Finding / Issue / Severity / lifecycle
  llm/         OpenAI-compatible async client (retries, 429 backoff)
  vcs/         git diff parsing (hunks → regions)
  context/     tree-sitter parsing + explorer agent loop (minimal evidence)
  analysis/    security + business-logic analyzers, anti-hallucination
  dedup/       semantic hashing (cross-source dedup key)
  store/       local SQLite (reviews / baseline / outbox / issue cache)
  sync/        offline-first outbox drain to the center
  lifecycle/   AI auto-close re-verification
  pipeline/    review orchestration
  mcp_server/  FastMCP server (stdio)
  review_center/ FastAPI middle platform + single-page web UI
skills/security-review/   the trigger skill
tests/                    end-to-end tests
```

## Test

```bash
pytest -q               # E2E: pipeline → outbox → HTTP → center, offline, autoclose
```
