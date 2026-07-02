# Tempest

Tempest is a local, non-prod-to-prod data leak detector exposed as an MCP server.
It answers one question about a codebase: **can non-production code (tests, dev
scripts, debug/logging paths) reach production resources or data?**

It is fully local — no cloud calls, no API keys, no LLM inference during graph
build or detection. It works with any MCP-capable coding agent (Claude Code,
Codex, GitHub Copilot, etc.).

## How it works

1. **`tempest_sync`** shells out to [`graphify`](https://pypi.org/project/graphifyy/)
   (`graphify update <repo>`, AST-only — no LLM, no API key) to build a code
   graph of the target repository — an AST-derived call/import/containment
   graph. The resulting `graph.json` (standard NetworkX node-link format) is
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

Installing Tempest gives you one command on your `PATH`, `tempest-server`, which
is the MCP server every client below points at. This is the **same on every
device** — no absolute venv paths to edit.

### Prerequisites

- **Python 3.10 or newer** — check with `python --version` (or `python3 --version`).
- **[`pipx`](https://pipx.pypa.io/)** or **[`uv`](https://docs.astral.sh/uv/)** —
  either one installs Tempest into an isolated environment so its dependencies
  don't collide with anything else on your machine.
  - Get pipx: `python -m pip install --user pipx && python -m pipx ensurepath`
    (then reopen your terminal so `pipx` is on `PATH`).
  - Or get uv: see [the uv install docs](https://docs.astral.sh/uv/getting-started/installation/).
- **Git**, to clone this repo.

### Steps

1. **Copy or Download the repo:**

   ```bash
   git clone https://github.com/Prabhat-Kr-Sahu/tempest_local_guard.git
   cd tempest_local_guard
   ```

   copy the repo  to  your device

2. **Install the `tempest-server` command** (pick one):

   ```bash
   pipx install ./tempest_mcp          # with pipx
   # or
   uv tool install ./tempest_mcp       # with uv
   ```

   This pulls in `graphifyy`, `networkx`, `mcp`, and `pyyaml` automatically —
   no separate `graphify` install needed.

3. **Verify it's on your PATH:**

   ```bash
   tempest-server
   ```

   `tempest-server` takes no arguments — it starts and waits on stdin for an MCP
   client to connect, which looks like a hang. That's expected; press **Ctrl-C**
   to quit. If the shell instead reports "command not found", your pipx/uv bin
   dir isn't on `PATH` — run `pipx ensurepath` (or `uv tool update-shell`) and
   reopen the terminal.

### Updating later

Pull the repo and reinstall in place:

```bash
git pull
pipx install --force ./tempest_mcp     # uv: uv tool install --force ./tempest_mcp
```

### Uninstalling

1. **Remove the `tempest-server` command:**

   ```bash
   pipx uninstall tempest-mcp          # if you installed with pipx
   # or
   uv tool uninstall tempest-mcp       # if you installed with uv
   ```

2. **Unregister it from any MCP client** you added it to:

   ```bash
   claude mcp remove tempest           # Claude Code
   codex mcp remove tempest            # Codex CLI
   ```

   For GitHub Copilot / Ollama bridges, delete the `tempest` entry from the
   config file you edited (`.vscode/mcp.json`, `mcp.json`, `servers.json`, etc.).

3. **(Optional) Delete cached state** from any repo you scanned — Tempest keeps
   everything under one directory, so removing it leaves no trace:

   ```bash
   rm -rf <repo>/.tempest
   ```

## Register with an MCP client

Point your agent at the `tempest-server` command you installed above. Pick the
client you use — the config shape is the same everywhere: a stdio server whose
`command` is `tempest-server`. After registering, confirm the four `tempest_*`
tools show up (e.g. `/mcp` in Claude Code / Codex) before using them.

### Claude Code

```bash
claude mcp add tempest -- tempest-server
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
      "command": "tempest-server"
    }
  }
}
```

Copilot CLI: `copilot mcp add` (interactive), or edit its MCP config file
directly with the same `command` shape as above.

### Codex CLI

```bash
codex mcp add tempest -- tempest-server
```

Or add directly to `~/.codex/config.toml`:

```toml
[mcp_servers.tempest]
command = "tempest-server"
```

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
         "command": "tempest-server"
       }
     }
   }
   ```
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

## Using the tools

You normally **don't call these tools by hand** — you ask your coding agent in
plain language and it picks the right tool with the right arguments. Every tool
takes a `repo_path` (the **absolute** path to the repo you want scanned); the
agent usually infers this from your open workspace.

The typical flow is two tools, in order:

> **You:** "Check this repo for non-prod-to-prod data leaks."
>
> The agent calls **`tempest_sync`** to build the graph, then **`tempest_detect`**
> to run the rules, and explains the findings in plain English.

Below is what each tool does, when it runs, and how to steer it.

### `tempest_sync(repo_path)` — build/refresh the graph

Run this **first**, and again after you change code. It runs `graphify update`
on the repo and caches the resulting graph under `<repo>/.tempest/`. Safe to
re-run any time.

> "Sync this repo so Tempest has a fresh graph."

Returns node/edge counts, the current git branch and commit, and a **warning if
you're not on the repo's default branch** (Tempest assumes prod tracks
`main`/`master`, so scanning a feature branch may misclassify).

### `tempest_detect(repo_path)` — run the leak rules

Requires a prior `tempest_sync`. Runs reverse reachability from every Production
Boundary Node and evaluates all three policy rules, then **saves the report** to
the local SQLite DB.

> "Now run leak detection and tell me what's risky."

Returns a structured report: summary counts plus a list of findings, each with
`rule` (a/b/c), `severity`, `source_node`/`target_node`, an evidence `path`, and
a suggested fix. Ask the agent to "explain finding 1" or "show me the path" to
drill in.

### `tempest_get_report(repo_path, scan_id=None)` — re-fetch a past scan

Cheap re-read of a previous `tempest_detect` result **without re-running
detection**. Omit `scan_id` for the latest scan; it also returns `scan_history`
so you can pick an older one.

> "Show me the last leak report again."
> "Compare the current findings with scan &lt;id&gt; from earlier."

### `tempest_classify_boundary(repo_path, node_id, ...)` — inspect or override a classification

Two modes:

- **Inspect** (pass only `node_id`): see why a node was tagged PROD/NON-PROD/PBN
  and the heuristics behind it. Use `node_id` values straight from a finding's
  `source_node`/`target_node`.

  > "Why did Tempest classify &lt;node_id&gt; as production?"

- **Override** (pass any of `set_env_tag`, `set_is_pbn`, `set_pbn_type`): pin a
  manual classification that **wins over every heuristic** on future scans.
  Stored in `<repo>/.tempest/boundary_overrides.json`.

  > "That's a test double, not prod — mark &lt;node_id&gt; as NON_PROD."
  > "Treat &lt;node_id&gt; as a production database boundary node."

Use overrides to kill false positives (a node wrongly seen as prod) or false
negatives (a real prod boundary the heuristics missed), then re-run
`tempest_detect`.

### Quick reference

| Tool | Purpose |
|---|---|
| `tempest_sync(repo_path)` | Build/refresh the graph for a repo. Run this first, and again after code changes. |
| `tempest_detect(repo_path)` | Run all 3 policy rules and return (and persist) a structured leak report. |
| `tempest_get_report(repo_path, scan_id=None)` | Re-fetch a previous scan (default: latest) plus scan history, without re-running detection. |
| `tempest_classify_boundary(repo_path, node_id, set_env_tag=None, set_is_pbn=None, set_pbn_type=None)` | Inspect why a node was classified PROD/NON-PROD/PBN, or set a manual override. |

## Configuration

Tempest ships defaults in `src/tempest/data/tempest.default.yaml` (boundary heuristics,
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
- Detection quality depends entirely on `graphify update`'s AST coverage
  for the target language/framework.

## Development

Work from a venv with an editable install (so tests import `tempest` and the
`tempest-server` script resolves):

```bash
cd tempest_mcp
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
```

Test fixtures live in `tests/fixtures/`:
- `leaky_repo/` — one deliberately planted leak per rule, plus clean
  sibling files (false-positive control).
- `clean_repo/` — leak-free subset only (negative control).
