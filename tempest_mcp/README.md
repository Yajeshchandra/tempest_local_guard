# Tempest

Tempest is a local, non-prod-to-prod data leak detector exposed as an MCP server.
It answers one question about a codebase: **can non-production code (tests, dev
scripts, debug/logging paths) reach production resources or data?**

It is fully local — no cloud calls, no API keys, no LLM inference during graph
build or detection. It works with any MCP-capable coding agent (Claude Code,
Codex, GitHub Copilot, etc.).

## How it works

1. **`tempest_sync`** shells out to [`graphify`](https://pypi.org/project/graphifyy/)
   (`graphify extract <repo>`) to build a code graph of the target repository —
   an AST-derived call/import/containment graph, no LLM required for pure code
   repos. The resulting `graph.json` (standard NetworkX node-link format) is
   cached under `<repo>/.tempest/`.
2. Tempest classifies every node as **PROD** or **NON-PROD** using an ordered
   heuristic chain (manual overrides > path globs > env-file markers > folder
   naming conventions > string-literal content), and flags **Production
   Boundary Nodes (PBNs)** — PROD nodes that are structurally a resource
   boundary (database/storage/messaging/network client).
3. **`tempest_detect`** runs reverse reachability (`networkx.ancestors`) from
   every PBN and evaluates 3 policy rules:
   - **(a)** hardcoded prod secrets/identifiers in non-prod code
   - **(b)** test/seed code that calls/instantiates/uses a prod resource
   - **(c)** prod data reaching a non-prod logging/debug sink
4. Findings are returned as structured JSON (rule, severity, source/target
   node, evidence path, suggested fix) and persisted to a local SQLite
   database for later retrieval.

## Install

Requires Python 3.10+. Run these from inside `tempest_mcp/` (the folder this
README is in) — the venv and the package must live together since Tempest
reads `config/tempest.default.yaml` via a filesystem-relative path.

**Windows (PowerShell):**

```powershell
cd tempest_mcp
python -m venv .venv
.venv\Scripts\python.exe -m ensurepip --upgrade   # only needed if the next line errors "No module named pip"
.venv\Scripts\python.exe -m pip install -e .
```

Always call scripts as `.venv\Scripts\python.exe` (or prefix with `.\`) —
PowerShell parses a bare `.venv\Scripts\pip` as a module-qualified command
name and fails with an `Import-Module` error, not a real path.

**macOS / Linux:**

```bash
cd tempest_mcp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

This pulls in `graphifyy`, `networkx`, `mcp`, and `pyyaml` automatically.

> If `python -m venv` produces a venv with no `pip`/`pip.exe` in
> `Scripts`/`bin` (rare, but happens with some system Python installs), run
> `python -m ensurepip --upgrade` inside that venv first — no need to
> recreate it.

## Register with an MCP client

`pip install -e .` installs a `tempest-server` console-script entry point
(defined in `pyproject.toml`'s `[project.scripts]`) straight into the venv's
`Scripts`/`bin` folder — so every client below points at the same one
command, no need to spell out `python -m tempest.server`:

- Windows: `C:\path\to\tempest_mcp\.venv\Scripts\tempest-server.exe`
- macOS/Linux: `/path/to/tempest_mcp/.venv/bin/tempest-server`

Swap in your actual venv path in the examples below.

### Claude Code

```powershell
claude mcp add tempest -- C:\path\to\tempest_mcp\.venv\Scripts\tempest-server.exe
```

```bash
claude mcp add tempest -- /path/to/tempest_mcp/.venv/bin/tempest-server
```

`-s user` instead of the default `-s local` registers it for every project,
not just the current one. Verify with `claude mcp list` or `/mcp` inside a
session.

### GitHub Copilot (VS Code / Copilot CLI)

VS Code: add to `.vscode/mcp.json` (workspace) or your user `mcp.json`:

```json
{
  "servers": {
    "tempest": {
      "type": "stdio",
      "command": "C:\\path\\to\\tempest_mcp\\.venv\\Scripts\\tempest-server.exe"
    }
  }
}
```

(macOS/Linux: `"command": "/path/to/tempest_mcp/.venv/bin/tempest-server"`.)

Copilot CLI: `copilot mcp add` (interactive), or edit its MCP config file
directly with the same `command` shape as above.

### Codex CLI

```powershell
codex mcp add tempest -- C:\path\to\tempest_mcp\.venv\Scripts\tempest-server.exe
```

Or add directly to `~/.codex/config.toml`:

```toml
[mcp_servers.tempest]
command = "C:\\path\\to\\tempest_mcp\\.venv\\Scripts\\tempest-server.exe"
```

(macOS/Linux: `command = "/path/to/tempest_mcp/.venv/bin/tempest-server"`.)

Check it's active with `/mcp` inside the Codex TUI.

### Ollama

Ollama has **no native MCP client** as of this writing (the feature request,
[ollama/ollama#7865](https://github.com/ollama/ollama/issues/7865), is still
open) — it can run local tool-calling models but doesn't speak MCP directly.
To use Tempest with an Ollama-served model, put a small bridge in between
that exposes MCP tools to Ollama's function-calling API. Two practical options:

1. **[MCPHost](https://github.com/mark3labs/mcphost)** — a Go CLI that
   drives an MCP server and forwards its tools to any Ollama model:
   ```powershell
   go install github.com/mark3labs/mcphost@latest
   ```
   `servers.json`:
   ```json
   {
     "mcpServers": {
       "tempest": {
         "command": "C:\\path\\to\\tempest_mcp\\.venv\\Scripts\\tempest-server.exe"
       }
     }
   }
   ```
   (macOS/Linux: `"command": "/path/to/tempest_mcp/.venv/bin/tempest-server"`.)
   Run: `mcphost -m ollama:qwen3 --config servers.json`, then ask it to
   check the repo for leaks — it'll invoke `tempest_sync`/`tempest_detect`
   through the bridge.
2. **[mcp-client-for-ollama](https://pypi.org/project/mcp-client-for-ollama/)**
   (`pip install mcp-client-for-ollama`, `ollmcp mcp add tempest ...`) — a
   TUI client with the same idea, saved server list, model switching.

Use a tool-calling-capable local model (14B+ params in practice — Qwen 3,
Llama 3.1/3.3, Mistral, Hermes 3 all work); smaller models tend to ignore or
mis-invoke tool schemas, which matters here since `tempest_detect`'s
structured JSON is meant to be read and explained by the model, not just
echoed back.

## Usage

Ask your agent, in natural language, something like:

> "Check this repo for non-prod-to-prod data leaks."

The agent will call `tempest_sync` (build/refresh the graph) then
`tempest_detect` (run the rules) and explain the structured findings.

### Tools

| Tool | Purpose |
|---|---|
| `tempest_sync(repo_path)` | Build/refresh the graph for a repo. Run this first, and again after code changes. |
| `tempest_detect(repo_path)` | Run all 3 policy rules and return a structured leak report. |
| `tempest_get_report(repo_path, scan_id=None)` | Re-fetch a previous scan (default: latest) plus scan history, without re-running detection. |
| `tempest_classify_boundary(repo_path, node_id, set_env_tag=None, set_is_pbn=None, set_pbn_type=None)` | Inspect why a node was classified PROD/NON-PROD/PBN, or set a manual override. |

## Configuration

Tempest ships defaults in `config/tempest.default.yaml` (boundary heuristics,
PBN patterns, sink patterns, sensitive-data keywords, known prod
identifiers). On first `tempest_sync`, a copy is written to
`<repo>/.tempest/tempest.config.yaml` — edit it to override any default for
that repo (values are deep-merged; your values win). Common edits:

- `boundary.path_overrides` — force specific globs to PROD/NON-PROD.
- `known_prod_identifiers` — literal secrets/hostnames Rule (a) should flag.
- `pbn_patterns` — add label keywords for resource classes specific to your
  codebase (e.g. your internal DB client's class name).

Manual per-node overrides (via `tempest_classify_boundary`) always win over
every heuristic and are stored in `<repo>/.tempest/boundary_overrides.json`.

## Local state

Every scanned repo gets a `.tempest/` directory (add it to `.gitignore` —
Tempest does this automatically on first sync):

```
<repo>/.tempest/
  graphify-out/            graphify's own working dir
  graph.json                canonical graph input
  tempest.config.yaml       per-repo config overrides
  boundary_overrides.json   manual PROD/NON-PROD overrides
  tempest.db                 scan history + findings (SQLite)
  last_sync.json
```

## Known MVP limitations

- **Rule (b)** approximates "writes to a prod resource" using
  `calls`/`instantiates`/`uses` edges, since graphify has no explicit
  write-edge relation. A read-only call into a PBN from test code would also
  match.
- Boundary classification is heuristic (path/filename/folder/content-regex),
  not a full data-flow or type analysis. Under-tagged nodes default to
  NON-PROD (a deliberate choice to avoid false negatives on leak detection,
  at the cost of occasionally treating an unrelated NON-PROD node as a
  reachability ancestor).
- Detection quality depends entirely on `graphify extract`'s AST coverage
  for the target language/framework.

## Development

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest tests/ -v
```

Test fixtures live in `tests/fixtures/`:
- `leaky_repo/` — one deliberately planted leak per rule, plus clean
  sibling files (false-positive control).
- `clean_repo/` — leak-free subset only (negative control).
