# Tempest — MVP Overview

Tempest is a **local, non-prod-to-prod data-leak detector** exposed as an MCP
server. It answers one focused question about a codebase:

> **Can non-production code (tests, dev scripts, debug/logging paths) reach
> production resources or data?**

It runs **fully local** — no cloud calls, no API keys, no LLM inference during
graph build or detection — and plugs into any MCP-capable coding agent (Claude
Code, Codex, GitHub Copilot, and Ollama via a bridge).

---

## What it does (in one pass)

1. **Builds a code graph** of the target repo by shelling out to
   [`graphify`](https://pypi.org/project/graphifyy/) (`graphify update`,
   AST-only — no LLM). The output `graph.json` (NetworkX node-link format) is
   the sole data contract.
2. **Classifies every node** as `PROD` or `NON-PROD`, and flags **Production
   Boundary Nodes (PBNs)** — PROD nodes that are structurally a resource
   boundary (database / storage / messaging / network client).
3. **Runs reverse reachability** from every PBN and evaluates **3 policy rules**
   to find non-prod code that touches prod.
4. **Returns structured findings** (rule, severity, source/target node, evidence
   path, suggested fix) and **persists** them to a local SQLite DB for re-fetch.

---

## Architecture

Tempest is two engines over a shared graph, wrapped in an MCP server.

```
                        ┌──────────────────────────────────────────────┐
   MCP client           │                 tempest-server                │
 (Copilot / Claude ─────┤            (stdio MCP, server.py)             │
  Code / Codex)         │   tools: sync · detect · get_report ·         │
                        │          classify_boundary                    │
                        └───────────────┬──────────────────────────────┘
                                        │
             ┌──────────────────────────┴───────────────────────────┐
             ▼                                                       ▼
   ┌───────────────────────────┐                     ┌───────────────────────────┐
   │  RIE                       │                     │  LDE                       │
   │  Repository Intelligence   │   graph + labels    │  Leak Detection Engine     │
   │  Engine (thin graphify     │ ──────────────────► │  (reachability + rules)    │
   │  layer)                    │                     │                            │
   │                            │                     │                            │
   │  • sync.py  → graphify      │                     │  • orchestrator.py         │
   │  • graph_loader.py          │                     │  • pbn_selector.py         │
   │  • env_map.py (PROD chain)  │                     │  • reachability.py         │
   │  • boundary.py (PROD/PBN)   │                     │  • policy.py (rules a/b/c) │
   │  • branch_state.py (git)    │                     │  • path_reconstruct.py     │
   └──────────────┬─────────────┘                     │  • path_filter.py          │
                  │                                    │  • evidence.py / report.py │
                  ▼                                    └──────────────┬─────────────┘
        ┌──────────────────┐                                         │
        │  graphify (CLI)   │  AST-only, no LLM                       ▼
        │  graph.json       │                            ┌───────────────────────────┐
        └──────────────────┘                             │  storage/db.py (SQLite)    │
                                                         │  scan history + findings   │
                                                         └───────────────────────────┘
```

All per-repo state lives under `<repo>/.tempest/` (auto-added to `.gitignore`).

### Component responsibilities

| Layer | Module | Responsibility |
|---|---|---|
| **MCP** | `server.py` | Exposes the 4 tools over stdio; thin request/response glue. |
| **RIE** | `sync.py` | Shells out to `graphify update` (AST-only), records branch state, writes `last_sync.json`. |
| | `graph_loader.py` | Loads `graph.json` into a NetworkX graph. |
| | `env_map.py` | Ordered PROD/NON-PROD heuristic chain (overrides → path globs → env-file markers → folder naming → string content). |
| | `boundary.py` | Applies the PROD chain + content-regex upgrade, then flags PBNs via config-driven `pbn_patterns`. |
| | `branch_state.py` | Detects current branch/commit + whether it's the repo's default branch. |
| **LDE** | `orchestrator.py` | Full pipeline: load graph → classify → evaluate rules → build report. |
| | `pbn_selector.py` | Selects the set of Production Boundary Nodes to reach *from*. |
| | `reachability.py` | Reverse reachability (`networkx.ancestors`) from each PBN. |
| | `policy.py` | The 3 policy rules as independent, unit-testable functions. |
| | `path_reconstruct.py` / `path_filter.py` | Build and filter the evidence path from a non-prod source to a PBN. |
| | `evidence.py` / `report.py` | Shape `Finding` objects and the structured report. |
| **Storage** | `db.py` | SQLite scan history + findings (`tempest.db`). |
| **Config** | `config.py` | Loads defaults + per-repo `tempest.config.yaml` (deep-merged). |

---

## The detection pipeline

```
graph.json ─► load graph ─► classify nodes (PROD / NON-PROD)
                                   │
                                   ├─► flag PBNs (PROD + resource boundary)
                                   │
                                   ▼
              for each PBN: reverse-reachability (networkx.ancestors)
                                   │
                                   ▼
                  evaluate 3 policy rules over reachable non-prod nodes
                                   │
                                   ▼
        Findings (rule, severity, source/target, evidence path, fix) ─► SQLite
```

### The 3 policy rules

| Rule | What it catches |
|---|---|
| **(a)** | Hardcoded **prod secrets / identifiers** (connection strings, hostnames, known prod IDs) living in **non-prod** code. |
| **(b)** | **Test/seed code** that calls, instantiates, or uses a **prod resource** (a PBN). |
| **(c)** | **Prod data reaching a non-prod logging/debug sink** (data flowing out to a debug/log path). |

### Boundary classification (how a node becomes PROD / PBN)

PROD tagging runs an **ordered heuristic chain** (first match wins, most
authoritative first):

1. **Manual overrides** (`boundary_overrides.json`) — always win.
2. **Path globs** (`boundary.path_overrides`).
3. **Env-file markers**.
4. **Folder naming conventions** (e.g. `tests/`, `scripts/`, `dev/` → NON-PROD).
5. **String-literal content** — a regex pass near the node's source location
   can *upgrade* a node to PROD (e.g. an embedded connection string).

A node is a **PBN** only if it is **both** PROD-tagged **and** structurally a
resource boundary (matched against the config-driven `pbn_patterns` table).

> **Default bias:** under-tagged nodes default to **NON-PROD** — a deliberate
> choice that favors catching leaks over silent false negatives.

---

## Features

- **Fully local & offline** — no cloud, no API keys, no LLM in the build or
  detection path.
- **Agent-native** — four MCP tools any MCP client can call in plain language.
- **Language-agnostic graph** — coverage follows `graphify`'s AST extractors.
- **Explainable findings** — every finding carries an **evidence path** from the
  non-prod source to the prod boundary, plus a suggested fix.
- **Tunable classification** — per-repo `tempest.config.yaml` for path
  overrides, known prod identifiers, and PBN patterns.
- **Manual overrides that stick** — pin a node PROD/NON-PROD/PBN;
  overrides beat every heuristic on future scans.
- **Persistent scan history** — findings saved to SQLite; re-fetch or compare
  past scans without re-running detection.
- **Branch-aware** — warns when you scan a non-default branch (prod is assumed
  to track `main`/`master`), so you know the graph may not reflect deployed code.

---

## The MCP tools

| Tool | Purpose |
|---|---|
| `tempest_sync(repo_path)` | Build/refresh the graph for a repo. **Run first**, and again after code changes. |
| `tempest_detect(repo_path)` | Run all 3 policy rules; return **and persist** a structured leak report. |
| `tempest_get_report(repo_path, scan_id=None)` | Re-fetch a previous scan (default: latest) + scan history, **without** re-running detection. |
| `tempest_classify_boundary(repo_path, node_id, …)` | Inspect **why** a node was classified PROD/NON-PROD/PBN, or set a manual override. |

Typical flow:

> **You:** "Check this repo for non-prod-to-prod data leaks."
> → agent calls `tempest_sync`, then `tempest_detect`, and explains the findings.

---

## Use cases

- **Pre-merge / CI guardrail** — catch a test that points at the production
  database, or a debug script logging prod PII, before it ships.
- **Secret-sprawl audit** — surface hardcoded prod connection strings /
  hostnames sitting in non-prod code (Rule a).
- **Blast-radius review** — for a given prod resource (PBN), see every non-prod
  path that can reach it via the evidence graph.
- **Onboarding / architecture map** — understand where prod boundaries are and
  what code legitimately (or accidentally) crosses into them.
- **Incident retro** — re-fetch and compare past scans to see when a leak path
  was introduced.
- **Agent-assisted remediation** — the structured findings + suggested fixes are
  meant to be read and acted on by your coding agent, not just echoed.

---

## Local state layout

Every scanned repo gets a `.tempest/` directory:

```
<repo>/.tempest/
  graphify-out/            graphify's own working dir (opaque)
  graph.json                canonical graph input (NetworkX node-link)
  tempest.config.yaml       per-repo config overrides (deep-merged over defaults)
  boundary_overrides.json   manual PROD/NON-PROD/PBN overrides (win over heuristics)
  tempest.db                scan history + findings (SQLite)
  last_sync.json            summary of the last successful sync
```

---

## Known MVP limitations

- **Rule (b)** approximates "writes to a prod resource" using
  `calls`/`instantiates`/`uses` edges, since graphify has no explicit write-edge
  relation — a **read-only** call into a PBN from test code also matches.
- **Boundary classification is heuristic** (path / filename / folder /
  content-regex), not full data-flow or type analysis.
- **Detection quality tracks `graphify update`'s AST coverage** for the target
  language/framework — unsupported languages yield a sparse graph.
- **Prod = default branch assumption** — scanning a feature branch reflects
  in-progress code, not what's deployed (Tempest warns, doesn't block).

---

## At a glance

| | |
|---|---|
| **Runs** | Locally, offline, as an MCP stdio server (`tempest-server`) |
| **Inputs** | A repo path (absolute) |
| **Engine** | `graphify` (AST graph) → PROD/PBN classification → reachability → 3 rules |
| **Outputs** | Structured JSON findings + evidence paths, persisted to SQLite |
| **Tools** | `sync` · `detect` · `get_report` · `classify_boundary` |
| **State** | `<repo>/.tempest/` (git-ignored) |
