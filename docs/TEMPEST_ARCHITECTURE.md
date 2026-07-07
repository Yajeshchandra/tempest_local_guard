# Tempest — Architecture & Use-Case Documentation

Deep read of the merged **V1.01 + v1 Payload Engine** branch (`tempest_mcp/`).
Covers what the tool is for, how it actually works internally, and a ranked
list of what could be done better (including two live bugs found while reading).

---

## 1. Use case — the one question it answers

> **Can non-production code (tests, dev scripts, seed data, debug/logging paths)
> reach production resources or production data?**

The threat is mundane and common: a test file imports the real prod DB client,
a seed script points at the prod bucket, a debug logger dumps a real customer
record, or an `AKIA…` key is hardcoded in a fixture. Each is a data-leak or
blast-radius risk that normal linters and secret-scanners only partially catch,
because the danger is *structural* (who-can-reach-what), not just *textual*
(is-there-a-secret-string).

Tempest ships as a **fully local MCP server** — no cloud, no API keys, no LLM in
the build or detection path — so any MCP coding agent (Claude Code, Codex,
Copilot) can drive it in plain language over stdio.
(`src/tempest/server.py`)

It attacks the problem on **two independent tiers**:

| Tier | Question | Engine | Needs a graph? |
|------|----------|--------|----------------|
| **1 — Structural** | Can non-prod code *reach* a prod resource? | Graph reachability (RIE + LDE) | Yes (`tempest_sync`) |
| **2 — Content** | Is there a real secret/PII *in* the bytes? | Payload Engine (regex/NER/entropy) | No (standalone walk) |

Tier 1 is the original V1.01 work. Tier 2 is the v1 Payload Engine you merged in.
They are exposed as separate tools and do **not** currently share a pipeline
(see §6 and §7).

---

## 2. High-level architecture

```
                        ┌──────────────────────── MCP tools (server.py) ────────────────────────┐
                        │ tempest_sync  tempest_detect  tempest_get_report                        │
                        │ tempest_classify_boundary     tempest_scan_content                      │
                        └───────────────┬───────────────────────────────────┬──────────────────────┘
                                        │ Tier 1 (structural)                │ Tier 2 (content)
                 ┌──────────────────────▼───────────────────────┐   ┌────────▼───────────────────────┐
                 │  RIE — Repository Intelligence Engine (rie/)  │   │  Payload Engine (payload/)      │
                 │  • sync.py     graphify update → graph.json   │   │  scan.py walks whole repo tree  │
                 │  • graph_loader.py  NetworkX DiGraph          │   │  engine.py routes by file type  │
                 │  • env_map.py  PROD/TEST/DEV/... path tagging │   │  regex_tool / ner_tool /        │
                 │  • boundary.py PROD + PBN classification      │   │  entropy_tool                   │
                 └──────────────────────┬───────────────────────┘   └────────┬───────────────────────┘
                                        │ produces                           │ produces
                          ┌─────────────▼──────────────┐            content_scan_report.json
                          │  RIM (rim.py) — the formal  │            (path-based env tag per finding)
                          │  contract: graph +          │
                          │  classifications + config   │
                          └─────────────┬──────────────┘
                                        │ consumed exclusively by
                 ┌──────────────────────▼───────────────────────┐
                 │  LDE — Leak Detection Engine (lde/)           │
                 │  orchestrator → policy (rules a/b/c) →        │
                 │  reachability / path_filter / pbn_selector →  │
                 │  report.py (JSON + markdown)                  │
                 └──────────────────────┬───────────────────────┘
                                        │ persisted to
                                  storage/db.py  (SQLite: scan history + findings)
```

The **RIM dataclass** (`rim.py`) is the deliberate seam: RIE knows about
graphify/AST/filesystem; LDE knows nothing except the RIM it's handed
(`graph`, `classifications`, `config`, `repo_root`). Detection logic is testable
without ever running graphify.

---

## 3. Tier 1 pipeline, end to end

### 3.1 `tempest_sync` — build the graph  (`rie/sync.py`)
1. Shells out to `graphify update <repo> --no-cluster` (AST-only, no LLM) as a
   black box. `graph.json` (NetworkX node-link JSON) is the *sole* data
   contract — graphify internals are never imported.
2. Caches it under `<repo>/.tempest/`, records branch/commit state, warns if
   you're not on the default branch (prod is assumed to track `main`/`master`,
   so scanning a feature branch may misclassify).
3. Windows guard: forces `GRAPHIFY_MAX_WORKERS=1` because graphify's parallel
   workers can inherit the capture pipe and hang `communicate()` forever
   (`sync.py:119`). A thoughtful, real-hardware-shaped workaround.

### 3.2 Classification — RIE  (`rie/env_map.py`, `rie/boundary.py`)
Every node is tagged through an **ordered heuristic chain, first match wins**
(`env_map.classify_env_for_path`):
1. Explicit glob `path_overrides` (prod / non_prod)
2. Env-file markers (`.env.prod` vs `.env.dev`)
3. Folder conventions (`prod/`, `tests/`, `fixtures/`, `dev/`) — with a priority
   order so `tests/prod_fixtures/` resolves to the more dangerous PROD tag
4. **Content regex** (`boundary.py`) — lowest priority, fires *only* when the
   path gave no signal at all. Crucially, it will **not** flip a `tests/` file
   to PROD just because it mentions a prod hostname in a comment — that's
   exactly the Rule (a) finding, not a boundary flip (`boundary.py:259`).

Unmatched → **NON-PROD by default** (deliberate: Tempest cares about things
*reaching* prod, so under-tagging must not create false negatives).

A **PBN (Production Boundary Node)** is a node that is *both* PROD-tagged *and*
structurally a resource boundary (database/storage/messaging/network), matched
via `pbn_patterns` against the node label, or — higher confidence — via
`scanner_findings` annotations (`database_url→database`, `s3_uri→storage`)
detected in the source (`boundary._classify_pbn`).

Manual overrides (`boundary_overrides.json`, set via `tempest_classify_boundary`)
win over **every** heuristic.

### 3.3 Detection — LDE  (`lde/orchestrator.py`, `lde/policy.py`)
`run_detection` loads graph → `classify_graph` → builds RIM → `evaluate_all_rules`
→ `Report` (JSON + markdown), persisted to SQLite.

**Rule (a) — hardcoded prod secret in non-prod code** (`policy.evaluate_rule_a`)
A classification-informed grep, *not* a traversal. For each non-prod source
file, scans string literals for `known_prod_identifiers` / `prod_identifier_patterns`
/ `secret_patterns`, with an entropy + digit/alpha gate and a
connection-string shape guard to cut noise.

**Rule (b) — test/seed code reaching a prod resource** (`policy.evaluate_rule_b`)
Reverse reachability (`networkx.ancestors`) from each database/storage/messaging
PBN, keeping only TEST-tagged ancestors connected through a
`calls`/`instantiates`/`uses` relation chain. Notably also checks
`nx.descendants` to handle graphify emitting edges backwards (PBN→test), and
filters sources to real function/method nodes (label ends `()`) so module and
docstring nodes don't multiply findings.

**Rule (c) — prod data reaching a non-prod sink** (`policy.evaluate_rule_c`)
Same reachability engine, source/target swapped: prod-data nodes (DB/storage
PBNs or PROD nodes matching `sensitive_data_keywords`) are the target, and it
looks for non-prod sink-labeled (`log`/`debug`/`dump`) function ancestors. Has
extra guards: dedupe prod-data nodes on the same chain, require the sink's
*first hop* to be a genuine prod node (spurious graphify edges are 2-node direct
hops), one finding per sink.

The rule code is unusually honest about its own limits — the "graphify has no
write-edge type, so this over-matches read-only calls" caveat is written into
the docstring (`policy.py:38`), matching the README's "Known MVP limitations".

---

## 4. Tier 2 — the Payload Engine  (`payload/`)

Exposed as `tempest_scan_content` → `scan.run_content_scan` → `PayloadEngine`.
Walks the whole repo tree (pruning `.git`, `node_modules`, `.venv`, …), routes
each file by extension/path, and emits findings tagged with a path-based env:

- **P-01** hardcoded credentials (AWS/GitHub/Slack/Stripe/GCP/JWT/DB URIs) — regex + entropy
- **P-02** secrets in `.env` files
- **P-04** customer PII in fixtures/seed data (email/SSN/card/IBAN) — NER-ish regex + density escalation
- **P-05** PII/secrets in Jupyter notebook cells *and outputs*
- **P-06** binary build artifacts staged for commit (flagged without reading)
- **P-07** auth tokens in VCR cassettes
- **P-08** secrets in IDE artifacts (`.vscode/settings.json`, …)

Design is defensively lazy in the good sense: never crashes the caller on a bad
file (`engine.scan` swallows per-file exceptions), entropy scan is skipped on
lines already flagged by regex, findings deduped on `file:line:type`. Writes its
own `content_scan_report.json`, entirely separate from the SQLite scan history.

---

## 5. MCP tool surface  (`server.py`)

| Tool | Purpose |
|------|---------|
| `tempest_sync(repo_path)` | Build/refresh the graph. Run first, and after code changes. |
| `tempest_detect(repo_path)` | Run rules a/b/c; return + persist structured report. |
| `tempest_get_report(repo_path, scan_id?)` | Re-read a past scan without re-running. |
| `tempest_classify_boundary(repo_path, node_id, …)` | Inspect *why* a node was classified, or pin an override. |
| `tempest_scan_content(repo_path)` | Tier-2 content scan; no graph needed. |

Every tool returns a plain dict with `ok`/`error` — no exceptions cross the MCP
boundary. The agent is expected to *explain* findings, so `tempest_detect` also
returns a `markdown_report`.

---

## 6. Honest assessment: how well does it solve the problem?

**Strengths**
- The structural angle is genuinely valuable and hard to get from a plain
  secret-scanner — "test code can construct the prod DB client" is a real class
  of bug most tools miss.
- Clean RIE↔LDE seam via RIM makes the rules unit-testable in isolation; 28
  tests pass, fixtures include planted-leak *and* false-positive controls.
- Fully local / no-API-key is a real adoption advantage for security tooling.
- The code is refreshingly candid about its own heuristics and limits.

**Fundamental ceilings (inherent, not bugs)**
- Everything rides on graphify's AST coverage and edge quality. The rules are
  visibly working *around* graphify (backwards edges, spurious 2-node hops) —
  detection quality is capped by the graph's quality.
- No real data-flow/taint analysis: reachability over call/import edges is a
  proxy for "data flows," and Rule (b) explicitly can't tell a read from a write.
- Classification is path/label/regex heuristics — no type analysis.

---

## 7. What could be done better (ranked)

### 🔴 P0 — Live bugs
1. **Incremental-sync fast path is dead code** (`rie/sync.py:173`).
   The commit-unchanged shortcut calls `logger.info(...)`, but `sync.py` never
   imports or defines `logger`. It's wrapped in `try/except Exception: pass`, so
   every "unchanged" sync raises `NameError`, is swallowed, and falls through to
   a **full `graphify update`**. The advertised "~0.01s cached sync" never
   happens. Fix: add `logger = logging.getLogger("tempest")` (one line).
   *Runnable check:* sync twice on an unchanged repo; assert the second returns
   before spawning graphify.

2. **Payload Engine docstrings describe a different codebase** (`payload/engine.py:18-25`, `126-129`).
   Carried over verbatim from v1's separate lineage: they reference an
   `orchestrator.py` that "calls this engine for every git commit" and
   `from leak_detector_agent.engines.payload_engine import PayloadEngine`. In
   this repo it's driven by `payload/scan.py` on a whole-tree walk, there is no
   git-hook orchestrator, and that import path doesn't exist. Misleading to the
   next reader — update or delete.

### 🟠 P1 — Integration debt from the merge
3. **The two tiers don't talk.** Tier 2 is a bolted-on parallel tool
   (`tempest_scan_content`), not wired into `tempest_detect`. The highest-value
   product move is to let structural context *rank* content findings: a P-01
   secret in a file whose nodes are reachable from a PBN is far more urgent than
   one in a dead example. Right now the user has to correlate two reports by hand.
4. **Duplicated secret/entropy logic.** There are now two entropy
   implementations (`policy._shannon_entropy` and `payload/entropy_tool.calculate_entropy`)
   and two secret-detection passes (Rule (a) literals vs Payload P-01). Same
   job, two code paths, two config surfaces (`secret_patterns` vs the engine's
   hardcoded regexes). Consolidate onto the Payload Engine and have Rule (a) call it.

### 🟡 P2 — Robustness / quality
5. **Rule (b) read-vs-write blindness** is the biggest precision gap and is
   already the whole premise of the `V1.03-Semantic` branch (LLM WRITE/READ
   check on the 2-3 candidate paths). Worth porting that filter here — it
   degrades gracefully to current behaviour with no LLM.
6. **Per-process caches are never cleared** (`boundary._SOURCE_TEXT_CACHE`,
   module-level `re.compile`). Fine for a one-shot CLI, but the MCP server is
   long-lived across many repos in one session — the file-text cache is keyed by
   path and could serve stale content after an edit + re-sync within the same
   process. Clear it per detection run.
7. **`tempest_scan_content` walks the tree with no size/count cap.** A large
   monorepo or a stray multi-GB file will read everything into memory line by
   line. Add a max-file-size skip and a file-count ceiling (the binary-ext guard
   helps but doesn't cover a giant `.json`).
8. **STAGING/QA/DEV tags are computed but barely used.** `env_map` produces a
   5-level ladder, but the rules only branch on TEST and PROD. Either use the
   granularity (e.g. STAGING→PROD reachability is also interesting) or collapse
   it to reduce surface.

### 🟢 P3 — Polish
9. `from __future__ import annotations` + `import shutil, pathlib` *inside*
   `run_graphify_extract` (`sync.py:145`) shadows the top-level `shutil` import —
   works, but it's a smell.
10. Rule (a) recomputes `_shannon_entropy(literal)` twice per match
    (`policy.py:340` and again at `:376`). Compute once.
11. No CI config in the repo despite a clean 28-test suite — one GitHub Action
    running `pytest` would lock in the "27/27→28/28" guarantee the analysis doc
    keeps citing.

---

## 8. One-paragraph summary

Tempest is a local, agent-driven leak detector that asks whether non-prod code
can structurally reach prod resources (Tier 1: graphify AST graph → PROD/PBN
classification → reverse-reachability rules a/b/c) and, separately, whether real
secrets/PII sit in the repo's bytes (Tier 2: the merged Payload Engine). The
structural tier is the differentiated, well-factored core; the content tier is a
solid standalone scanner that's currently bolted on rather than integrated. The
top opportunities are (1) fix the silently-dead incremental sync, (2) integrate
the two tiers so structure ranks content findings, and (3) port the
read-vs-write semantic filter to cut Rule (b)'s known false positives.
