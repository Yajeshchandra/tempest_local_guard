# Tempest — Plan to Make It Usable for Real Leak Detection (PoC)

Goal: get from "passes 28 synthetic tests" to "finds real non-prod→prod leaks in
a real repository, with tolerable noise, in a demo someone believes." This plan
is grounded in **actual measurements** of the current engine on real repos, not
theory.

Companion to `TEMPEST_ARCHITECTURE.md`, `TEMPEST_GRAPH_STRUCTURE.md`,
`TEMPEST_LANDSCAPE_AND_BENCHMARKING.md`.

---

## 0. The uncomfortable baseline (measured, not guessed)

I ran the real `run_detection()` engine against the two real synced repos:

| Repo | Nodes | Edges | PROD nodes | **PBNs** | Findings | Detect |
|------|-------|-------|-----------|----------|----------|--------|
| **realworld** | 176 | 325 | **0** | **0** | **0** | 0.5s |
| **kustomize** | 8,352 | 22,085 | 51 | **1** | **0** | 17.5s |
| leaky_repo (fixture) | 48 | 55 | ~10 | 1 | 2 ✅ | <0.1s |

**Root cause — the classification collapses on real layouts.** The env/boundary
heuristics depend on folder conventions (`prod/`, `dev/`, `tests/`). The fixtures
have them; real repos don't. So:
- **realworld** → 0 PROD, 0 PBN → *nothing is even a candidate*. (It's also a
  specs/markdown repo, not an app — bad target.)
- **kustomize** → 51 PROD nodes (all from the content-regex fallback catching
  prod-looking strings, since there's no `prod/` folder) but only **1 PBN** out
  of 8,352 nodes → detection surface ≈ a single node → 0 findings.

**The PoC's make-or-break problem is not the rules — it's boundary discovery.**
The reachability engine and the 3 rules are fine (they light up correctly on the
fixture). They have nothing to chew on because almost nothing gets tagged PROD or
recognized as a resource boundary on a real codebase.

Everything below is prioritized around fixing *that*.

---

## 1. Definition of "usable PoC" — the demo we must be able to give

A PoC succeeds if we can stand in front of someone and show, on a **real,
recognizable repo** (not our fixture):

> "Here is a real production database/bucket/queue client. Here is test/seed/debug
> code that can reach it. Tempest found it, showed the exact call path, and the
> finding is real — and it did NOT drown us in false positives."

Concrete acceptance criteria:

| # | Criterion | Target |
|---|-----------|--------|
| A | Runs end-to-end on ≥2 real repos via `tempest_sync`+`tempest_detect` | no crashes, <60s each |
| B | Finds ≥1 **true** non-prod→prod reachability leak per demo repo | with correct evidence path |
| C | **Precision ≥ ~70%** on the demo repos (noise is what kills PoCs) | FP rate humans tolerate |
| D | Every finding is actionable | rule + path + suggested fix, human-readable |
| E | One coherent story, not two disconnected reports | tiers integrated enough to rank |

We are explicitly **not** chasing full precision/recall benchmarks or multi-
language coverage for the PoC — that's the productization phase (see §6).

---

## 2. Critical path — boundary discovery that survives real repos

This is 70% of the PoC effort. The insight: **NON-PROD detection is easy and
universal; PROD-boundary detection is the hard part and must come from what the
code *does*, not where it lives.**

### 2.1 Detect resource boundaries by behavior, not by folder  ⬅ the core work
Real prod boundaries are **client instantiations**, not folder names. Add
detection for the actual API surfaces:
- DB drivers: `psycopg2.connect`, `pymongo.MongoClient`, `sqlalchemy.create_engine`, `redis.Redis`, JDBC URLs
- Cloud SDKs: `boto3.client('s3'|'rds'|'sqs'|...)`, `google.cloud.storage.Client`, Azure SDK clients
- Queues/streams: `kafka`, `KafkaProducer`, `pika`/RabbitMQ, `celery`
These appear in the graph as `label`/`calls`/`instantiates` targets. Extend
`pbn_patterns` (config-driven already — `boundary._classify_pbn`) with a real
library-name table, and use the `scanner_findings` path (connection-string regex)
that already exists but is underpowered.
*Files:* `data/tempest.default.yaml` (`pbn_patterns`, `scanner_patterns`), `rie/boundary.py`.
*Check:* on a real repo with a boto3/psycopg client, PBN count goes from ~1 to the
right handful.

### 2.2 Separate "is PROD" from "is a boundary"
Right now a node must be PROD *first* to even be considered a PBN
(`boundary.classify_node`: `if is_prod: _classify_pbn(...)`). On real repos almost
nothing is PROD, so boundaries are never checked. **Invert for resource
boundaries:** a node that instantiates a real DB/cloud client *is* a prod
boundary regardless of folder — the folder heuristic then classifies the
*callers* as prod vs non-prod. This one change is likely the single biggest
lever on real-repo yield.

### 2.3 Make NON-PROD detection robust (it mostly is)
Universal, reliable signals that already work: `tests/`, `test/`, `spec/`,
`*_test.py`, `*.test.js`, `conftest.py`, `fixtures/`, `seeds/`, `factories/`,
`scripts/`, `dev/`, `examples/`, `notebooks/`. Audit `folder_markers` in the
default config against real conventions; add the missing ones. This half is
low-risk.

### 2.4 A "prod config" signal
Real repos mark prod via config, not folders: `settings/production.py`,
`config/production.yaml`, `.env.production`, `ENV=production` guards. Add these to
`env_file_markers`/`path_overrides`. Cheap, high-value.

---

## 3. Curate real PoC target repos (you can't demo on fixtures)

Neither current real repo works (realworld = docs; kustomize = 1 PBN). Need 2–3
**deliberately chosen** repos where the leak story is real and visible:

- **Best:** a real app that has both a DB/cloud client AND a test/seed suite that
  touches it (many Django/Flask/FastAPI/Rails/Express apps do). Look for
  `seed.py`/`seeds/`, `conftest.py` fixtures that call `create_engine`, factories
  hitting real settings.
- **Fallback (fully legitimate for a PoC):** take a real OSS app and **plant 1–2
  realistic leaks** (a `conftest.py` that imports `settings.production`, a seed
  script pointing at a prod-shaped DSN). Label them. This is standard PoC
  practice — just disclose it.
- Keep our synthetic `leaky_repo` as the "it definitely works" control.

Pin each repo to a commit SHA and write a tiny `expected.json` (the known leaks)
so the demo is reproducible and we can state precision honestly.

---

## 4. Precision — the thing that actually kills PoCs

A leak detector that cries wolf gets uninstalled. Concrete noise-reducers, in
order of payoff:

1. **Gate on edge `confidence`/`weight`.** graphify marks edges `EXTRACTED` (1.0)
   vs `INFERRED` (0.8); Tempest currently ignores this (see graph-structure doc).
   Dropping or down-weighting `INFERRED` edges in Rule (b)/(c) is a near-free FP cut.
2. **Rule (b) read-vs-write heuristic (no LLM).** The core false positive is "test
   reads from prod DB" counted as "writes." A lazy heuristic gets most of the
   value: flag the target method name — `.write/.save/.insert/.update/.delete/.put/
   .create/.execute` → write (report); `.get/.read/.find/.query/.select/.scan` →
   read (downgrade/suppress). This is 80% of `V1.03-Semantic`'s benefit with zero
   dependency. Port the full LLM filter only post-PoC.
3. **Config allowlist / baseline.** Let a repo mark known-safe nodes (the
   `boundary_overrides.json` mechanism already exists — surface it in the demo so
   FPs are one command to silence). detect-secrets-style baseline.
4. **Confidence/severity on findings.** Rank by (edge confidence × rule certainty
   × PBN certainty) so the demo leads with the strong ones.

---

## 5. Fix the blocking bugs (small, do first)

From the architecture doc — these are quick and some distort the PoC:
1. **Dead incremental sync** (`rie/sync.py:173`, undefined `logger`) — makes every
   re-sync do a full 17s graphify run. One line. The PoC demo re-syncs; fix it.
2. **Misleading Payload Engine docstrings** — remove references to the non-existent
   `orchestrator.py`/git-hook so the next dev isn't misled.
3. **Per-process source-text cache never cleared** (`boundary._SOURCE_TEXT_CACHE`)
   — the long-lived MCP server can serve stale file content after an edit+resync
   in one session. Clear per detection run. Matters the moment we demo live edits.
4. **`Report.to_dict()` omits `prod_node_count`/`pbn_count`** (they came back
   `None` in my run) — expose them; they're the health signal that tells you
   classification is working before you trust the findings.

---

## 6. Minimal tier integration (for criterion E — one story)

Don't build the full integration. For the PoC, just **cross-reference**: after
`tempest_detect`, run the content scan and annotate any structural finding whose
`source_file` also has a Tier-2 secret hit ("this leaking test file *also*
hardcodes a prod credential"). One function, big narrative payoff. Full ranking
integration is post-PoC.

---

## 7. Explicitly OUT of scope for the PoC (say no now)

- Full precision/recall benchmark harness & competitor comparison → that's the
  *next* phase (`TEMPEST_LANDSCAPE_AND_BENCHMARKING.md`).
- LLM semantic WRITE/READ filter (`V1.03-Semantic`) → the name-heuristic (§4.2)
  is enough to prove the point.
- Multi-language coverage matrix → pick ONE ecosystem for the PoC (whatever the
  demo repo is; Python is the safest given graphify maturity).
- Git-history secret scanning, live credential verification → Tier-2 parity with
  gitleaks is not the PoC thesis.
- Real dashboards / CI integration / packaging polish.

---

## 8. Sequenced plan (what to actually do, in order)

| Step | Work | Why | Rough size |
|------|------|-----|-----------|
| 1 | Fix §5 bugs (dead sync, cache, to_dict counts) | Unblocks trustworthy re-runs | S |
| 2 | §2.1–2.2 behavior-based boundary detection + invert PROD-gate | **The core fix — makes real repos yield PBNs** | L |
| 3 | §2.3–2.4 robust NON-PROD + prod-config signals | Complete the classification | M |
| 4 | §3 curate + pin 2–3 real target repos (plant leaks if needed) | Something real to detect | M |
| 5 | Run, measure PROD/PBN/finding counts, iterate on 2–3 until criteria A–B met | Close the loop empirically | M |
| 6 | §4 precision passes (confidence gate, read/write heuristic, overrides) | Hit criterion C (~70% precision) | M |
| 7 | §6 minimal tier cross-reference | Criterion E, the coherent story | S |
| 8 | Write the demo script + `expected.json` per repo | The deliverable | S |

**Definition of done:** steps 1–8 complete and criteria A–E met on ≥2 pinned real
repos, with the synthetic `leaky_repo` as a green control.

---

## 9. The one-paragraph version

The engine works; the *inputs to it* don't survive real code. On real repos the
folder-based classification finds almost no production boundaries (kustomize: 1
PBN in 8,352 nodes; realworld: 0), so the rules have nothing to fire on. The PoC
is therefore ~70% a **boundary-discovery** problem: detect prod resources by the
clients they instantiate (boto3/psycopg/kafka/…) rather than by folder name, and
stop requiring a node to be "PROD" before it can be a boundary. Add robust
universal NON-PROD signals, a lightweight read-vs-write heuristic and an edge-
confidence gate for precision, curate 2–3 real (or realistically leak-planted)
target repos, fix the handful of small bugs, and wire a one-line cross-reference
between the two tiers. That is a believable, real leak-detection PoC — without
building the full benchmark, the LLM filter, or multi-language support.
