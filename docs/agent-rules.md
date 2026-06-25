# Triggering ClueScan from other AI coding tools

The Claude Code path uses the `/security-review` **Skill** (see
`skills/security-review/SKILL.md`): the agent judges that it just completed a
feature, then calls the MCP `review_diff` tool. The scan runs in ClueScan's own
process and the call is **debounced server-side** — so you only need to teach
each tool the same two-step behavior: *judge feature-done → call `review_diff`*.

Connect the MCP server once, then add the tool-specific instruction below.

## Connect the MCP server (all tools)

ClueScan runs as a stdio MCP server:

```json
{ "mcpServers": { "cluescan": { "command": "cluescan", "args": ["serve-mcp"] } } }
```

Cursor, Codex, Zed, Continue, etc. all accept an MCP server config like this
(see each tool's docs for the exact file). The `review_diff` tool and the
debounce behavior are identical regardless of caller.

## Cursor — `.cursor/rules/cluescan.mdc`

```mdc
---
description: Run a ClueScan security review after completing a feature
---

When you finish implementing or significantly changing a feature (not for
style/trivial/WIP edits), call the `review_diff` MCP tool from the `cluescan`
server. Relay its short summary to the user and link the Review Center. Don't
paste the full analysis — detail lives in the Review Center. Repeated calls are
debounced automatically, so just call it when a feature is done.
```

## Codex CLI — `AGENTS.md` (project root)

```md
## Security review

After completing a feature or a substantive security-relevant change
(auth, input handling, SQL/commands, crypto, authz, file/HTTP, secrets,
deserialization), call the `cluescan` MCP tool `review_diff` and relay its
summary. Skip for style/trivial/WIP edits. Full findings are in the Review
Center — don't dump them inline.
```

## Zed / generic

Add the equivalent instruction to your agent prompt / assistant rules:

> When a feature is completed, call the MCP tool `review_diff` (server
> `cluescan`). It debounces automatically. Relay only the short summary.

## Notes

- **Trigger point = feature completion** (the agent judges it), not every edit,
  not at commit — same model as the Claude Code skill.
- **Debounce** is server-side: bursts collapse to one scan; every caller gets
  the same summary. No client-side timing logic needed.
- **Cross-tool aggregation**: regardless of which tool triggered a finding, it
  flows to the Review Center tagged with `source_tool` and is deduped by semantic
  hash — so the same vuln reported by Cursor and Claude Code becomes one Issue.
