# Tempest PoC — Execution Plan (branch `poc-real-detection`)

Working plan for the `poc-real-detection` branch. Where `TEMPEST_POC_PLAN.md` is
the *strategy*, this is the *work breakdown*: the main problem split into
independent sub-problems, each with a concrete approach, the files it touches,
and a runnable check that says it's done.

**Method:** decompose → solve each sub-problem behind its own check → integrate.
Each sub-problem is a small, reviewable commit (or a short series). No sub-problem
is "done" without its check passing.

---

## The main problem

> **The engine works on synthetic fixtures but finds nothing on real repos,
> because it discovers almost no production boundaries in real code.**

Measured: kustomize = 1 PBN / 8,352 nodes → 0 findings; realworld = 0 PBN → 0
findings. The rules are fine; their *inputs* (PROD/boundary classification) don't
survive real repo layouts. Solving the PoC = making boundary discovery real, then
protecting precision, then proving it on real repos.

---

## Decomposition map

```
MAIN: detect real non-prod→prod leaks in real repos, at ~70% precision
│
├─ SP0  Foundation — fix blocking bugs & expose health signals   [unblocks everything]
├─ SP1  Boundary discovery — find prod resources by behavior     [THE core, biggest lever]
│   ├─ SP1a  library/client detection table (boto3/psycopg/…)
│   ├─ SP1b  invert the PROD-first gate for resource boundaries
│   └─ SP1c  connection-string / DSN boundary detection
├─ SP2  Environment classification for real layouts              [who's prod vs non-prod]
│   ├─ SP2a  robust universal NON-PROD signals
│   └─ SP2b  prod-config signals (settings/production, .env.production)
├─ SP3  Precision guards                                          [make findings trustworthy]
│   ├─ SP3a  edge-confidence gate (EXTRACTED vs INFERRED)
│   ├─ SP3b  read-vs-write name heuristic (no LLM)
│   └─ SP3c  surface overrides/baseline as the FP escape hatch
├─ SP4  Real target repos                                         [something real to detect]
├─ SP5  Measurement harness                                       [close the loop empirically]
├─ SP6  Minimal tier integration                                 [one coherent story]
└─ SP7  Demo packaging                                            [the deliverable]
```

Dependency order: **SP0 → SP1 → SP2 → (SP4, SP5 in parallel) → SP3 → SP6 → SP7.**
SP1 is the make-or-break; if SP1 doesn't lift PBN counts on a real repo, nothing
downstream matters, so it's validated first against a real repo via SP5.

---

## SP0 — Foundation (fix bugs, expose health signals)

**Problem:** two live bugs distort any measurement, and the engine hides the very
numbers we need to trust it.

**Solve:**
- Fix dead incremental sync — add `logger = logging.getLogger("tempest")` in
  `rie/sync.py` (the fast-path currently `NameError`s and silently does a full
  17s graphify run every time).
- Clear `boundary._SOURCE_TEXT_CACHE` at the start of each `classify_graph` run so
  the long-lived MCP process can't serve stale file text after edit+resync.
- Expose `prod_node_count` / `pbn_count` (and env-tag histogram) in
  `Report.to_dict()` — these are the health signals that tell us classification
  works *before* we trust findings.
- Delete the misleading Payload Engine docstrings referencing the nonexistent
  `orchestrator.py`/git-hook.

**Files:** `rie/sync.py`, `rie/boundary.py`, `lde/report.py`, `payload/engine.py`.
**Check:** sync an unchanged repo twice → 2nd returns in <0.1s (not 17s);
`to_dict()` contains non-null `pbn_count`; existing 28 tests still green.

---

## SP1 — Boundary discovery (the core)

**Problem:** a node must be tagged PROD *before* it's even checked for being a
boundary (`boundary.classify_node`). On real repos ~nothing is PROD-by-folder, so
boundaries are never found. Prod resources in real code are identified by *what
they instantiate*, not where they sit.

### SP1a — Library/client detection table
**Solve:** extend config `pbn_patterns` with a real table of resource-client
identifiers matched against node `label`/`norm_label` and `calls`/`instantiates`
targets:
- database: `psycopg2`, `pymysql`, `sqlalchemy.create_engine`, `MongoClient`, `redis.Redis`, `asyncpg`, JDBC
- storage: `boto3.client('s3')`, `boto3.resource('s3')`, `google.cloud.storage`, Azure Blob
- messaging: `KafkaProducer`, `pika`, `celery`, `boto3.client('sqs')`
- network/other: generic `boto3.client(...)`, cloud SDK clients → `network`

**Files:** `data/tempest.default.yaml`, `rie/boundary.py` (`_classify_pbn`).
**Check:** unit test — a node labelled `create_engine()` / `boto3.client('s3')`
classifies as PBN with the right `pbn_type`.

### SP1b — Invert the PROD-first gate for resource boundaries
**Solve:** if a node matches a real resource-client pattern, treat it as a
**boundary regardless of env tag**; the env heuristic then classifies its
*callers* as prod vs non-prod. Keep folder-based PROD as an additional signal, not
a precondition for boundary-hood.

**Files:** `rie/boundary.py` (`classify_node` ordering).
**Check:** on kustomize (or the first real target), PBN count rises from 1 to the
handful of actual DB/cloud clients present; verified via SP5.

### SP1c — Connection-string / DSN boundary detection
**Solve:** strengthen the existing `scanner_patterns`/`scanner_findings` path so a
literal `postgres://…@host/db`, `s3://bucket`, `mongodb+srv://…` marks its
enclosing node as a boundary of the mapped type. (Mechanism already exists in
`_annotate_scanner_findings`; it's just under-populated.)

**Files:** `data/tempest.default.yaml` (`scanner_patterns`), `rie/boundary.py`.
**Check:** a file with a hardcoded prod DSN yields a `database` PBN.

---

## SP2 — Environment classification for real layouts

**Problem:** deciding prod vs non-prod on repos that don't use `prod/`/`dev/`.

### SP2a — Robust universal NON-PROD signals
**Solve:** audit/extend `folder_markers` with conventions that are real and
universal: `tests/ test/ spec/ specs/ __tests__/ e2e/`, `*_test.py *.test.js
*.spec.ts conftest.py`, `fixtures/ factories/ seeds/ testdata/`, `examples/
samples/ scripts/ dev/ notebooks/`.
**Files:** `data/tempest.default.yaml`, possibly `rie/env_map.py` (filename globs).
**Check:** test suite over a table of real paths → expected env tags.

### SP2b — Prod-config signals
**Solve:** add `settings/production.py`, `config/production.*`, `.env.production`,
`application-prod.*` to `env_file_markers`/`path_overrides` → PROD.
**Files:** `data/tempest.default.yaml`.
**Check:** those paths classify PROD; `settings/test.py` stays non-prod.

---

## SP3 — Precision guards

**Problem:** once SP1/SP2 raise yield, false positives will appear; a noisy
detector gets uninstalled. Target ~70% precision on the demo repos.

- **SP3a — Edge-confidence gate.** graphify tags edges `EXTRACTED` (1.0) vs
  `INFERRED` (0.8); currently ignored. Drop or down-weight `INFERRED` edges in
  Rule (b)/(c) traversal. *File:* `lde/reachability.py` / `lde/path_filter.py`.
  *Check:* a leak that exists only via an INFERRED edge is suppressed (or flagged
  low-confidence).
- **SP3b — Read-vs-write heuristic (no LLM).** The main FP is "test *reads* prod
  DB" scored as a write. Classify the reached method by name: `write|save|insert|
  update|delete|put|create|execute|commit` → write (report); `get|read|find|query|
  select|scan|list|fetch` → read (downgrade/suppress). ~80% of V1.03-Semantic's
  value, zero dependency. *File:* `lde/policy.py` (Rule b). *Check:* fixture with a
  test→`.read()` prod call is downgraded; test→`.write()` stays high.
- **SP3c — Surface overrides/baseline.** The `boundary_overrides.json` mechanism
  exists; make "silence this finding" a one-command step in the demo (baseline of
  accepted findings). *File:* docs + a thin helper. *Check:* an overridden node
  drops out of the next run.

---

## SP4 — Real target repos

**Problem:** neither current real repo is demoable (realworld=docs, kustomize=1
PBN). Need real leak stories.

**Solve:** curate 2–3 real repos that have a DB/cloud client **and** test/seed code
that could reach it (Django/Flask/FastAPI/Rails/Express apps). Where a natural
leak isn't present, **plant 1–2 realistic ones** (a `conftest.py` importing
`settings.production`; a seed script with a prod-shaped DSN) and disclose it. Keep
synthetic `leaky_repo` as the green control.
**Deliverable:** `benchmark/corpus/<repo>@<sha>/` + `expected.json` (known leaks).
**Check:** each target syncs cleanly and graphify produces a non-trivial graph.

---

## SP5 — Measurement harness

**Problem:** SP1's success is an empirical claim ("PBN count went up") that must be
observed, not assumed.

**Solve:** a small runner (not a framework) that, per target repo: runs
sync+detect, prints env-tag histogram, PROD/PBN counts, findings by rule, and —
against `expected.json` — precision/recall. This is the feedback loop for tuning
SP1–SP3.
**File:** `benchmark/run.py` (~100 lines, stdlib + tempest imports).
**Check:** running it on `leaky_repo` reports 2/2 known leaks found, 0 FP.

---

## SP6 — Minimal tier integration

**Problem:** two disconnected reports isn't one story (PoC criterion E).

**Solve:** after `tempest_detect`, run the content scan and annotate any structural
finding whose `source_file` also has a Tier-2 secret hit ("this leaking test file
*also* hardcodes a prod credential"). One cross-reference function; no full merge.
**Files:** `lde/orchestrator.py` or a thin `lde/enrich.py`.
**Check:** a file that both leaks structurally and contains a planted secret shows
the combined annotation.

---

## SP7 — Demo packaging

**Solve:** a scripted narrative — sync → detect → show ranked findings with paths
and fixes → silence one FP via override → re-run. Written up with the
`expected.json` so precision is stated honestly.
**Files:** `docs/DEMO.md`, `benchmark/`.
**Check:** the full script runs top-to-bottom and meets PoC criteria A–E from
`TEMPEST_POC_PLAN.md`.

---

## Definition of done (branch)

All 28 existing tests green + new sub-problem checks green, and on ≥2 pinned real
target repos: end-to-end run, ≥1 true leak each with correct path, precision ≥~70%,
findings actionable, one integrated story — with `leaky_repo` as a green control.

---

## Working agreement

- One sub-problem per commit (or short series); every commit leaves tests green.
- Each sub-problem lands its own runnable check (a `test_*.py` or an assert-based
  demo) — no logic without a check that fails when it breaks.
- SP1 is validated against a **real** repo (via SP5) before building SP3+ on top —
  fail fast on the make-or-break.
- Keep changes config-driven where the mechanism already is (`tempest.default.yaml`)
  rather than hardcoding.
```
