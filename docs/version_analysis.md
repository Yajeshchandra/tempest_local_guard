# Tempest — Version Comparison (v1 vs V1.01 vs V1.03-Semantic)

Analysis of `tempest_local_guard` branches: what each version does better and which to pick.

> **Branching note:** `V1.01` and `V1.03-Semantic` forked from the commit *just before* v1's final commit. So v1's standalone **Payload Engine content-scan tool** never exists on the feature branches — it was not rolled back, it lives on a separate lineage. `V1.03-Semantic` = `V1.01` + one semantic-filter commit.

---

## TL;DR

| Version | Best at | Pick it when |
|---------|---------|--------------|
| **v1** | Standalone regex/NER/entropy content scanning (Payload Engine) | You need the raw content-scan tool and don't need the newer detection/sync work |
| **V1.01** | Accurate structural leak detection, fast sync, clean architecture | Default choice for detection work — stable, 27/27 tests, no LLM needed |
| **V1.03-Semantic** | Everything in V1.01 + fewer false positives via LLM WRITE/READ check | You have an LLM endpoint and want the lowest false-positive rate |

**Recommendation:** Use **V1.03-Semantic** if you can configure an LLM (OpenAI/Anthropic/Ollama); otherwise **V1.01**. It degrades gracefully to V1.01 behaviour when no LLM is configured, so there's little downside to V1.03 beyond the extra `litellm` dependency.

---

## What each version is better at

### v1 — the only one with the Payload Engine
- **Better:** ships the standalone content-scan tool (`payload/engine.py` + `regex_tool`, `ner_tool`, `entropy_tool`, `scan.py`) for raw secret/PII scanning.
- **Worse:** older detection engine with 5 failing tests (pre-existing regressions), slower sync (no caching bypass), loose RIE↔LDE coupling, no markdown reporting.

### V1.01 — accuracy, speed, architecture
Better than v1 on every axis except the missing Payload Engine:

- **Detection accuracy:** fixed all 5 test regressions → **27/27 pass**. Rule B handles graphify's backwards edges (`nx.descendants()`); Rule C filters kill false positives from method/rationale nodes.
- **More coverage:** Rule A now also triggers on `secret_patterns` (AWS `AKIA…` keys, private-key headers), not just prod identifiers.
- **Smarter classification:** PBN classification reads `scanner_findings` off graph nodes (database_url→database, s3_uri→storage) before label heuristics — no extra file I/O.
- **Faster sync:** dropped hardcoded `--force` so graphify uses its own cache (46s→30s on Kustomize); `git rev-parse HEAD` bypass returns cached result in ~0.01s when nothing changed.
- **Cleaner architecture:** formal `RepositoryIntelligenceModel` (RIM) dataclass replaces loose `(graph, classifications, config)` tuples — strict RIE↔LDE boundary.
- **Better output:** `Report.to_markdown()`; `tempest_detect` returns a `markdown_report` alongside JSON.
- **Ops:** new `diagnose.py` + tests; higher reachability caps (`max_paths` 10, `max_path_length` 50).

### V1.03-Semantic — fewest false positives
Everything in V1.01, **plus** the semantic filter:

- **Better precision:** an LLM verifies whether a test→prod DB edge is a destructive **WRITE** vs a harmless **READ**, and drops reads — cutting Rule B false positives.
- **Cheap by design (lazy):** the LLM runs only on the 2–3 structural candidate paths Rule B finds, never the full 8,000+ node graph. Fast and low-cost.
- **Flexible:** `litellm` dependency lets you point at OpenAI, Anthropic, or local Ollama.
- **Safe fallback:** with no LLM configured it behaves exactly like V1.01 (tests still 27/27).
- **Cost:** adds a runtime dependency (`litellm`) and requires an LLM endpoint to gain the benefit.

---

## Decision guide

- **Need raw content scanning (regex/NER/entropy)?** → v1 (or port the Payload Engine forward).
- **Need reliable structural detection, no LLM, offline?** → V1.01.
- **Want the lowest false-positive rate and have an LLM?** → V1.03-Semantic.

**Gap:** no single branch has both the Payload Engine *and* the V1.01/V1.03 detection improvements. Combining them requires a merge — they're on separate lineages.
