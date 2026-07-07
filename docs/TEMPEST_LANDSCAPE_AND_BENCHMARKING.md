# Tempest — Competitive Landscape & Benchmarking Plan

Companion to `TEMPEST_ARCHITECTURE.md`. Two parts:
1. **Existing solutions** that solve some or all of the same problem, and where
   Tempest actually differs.
2. **How to benchmark ourselves** — datasets, metrics, comparison baselines, and
   a concrete harness so "we're better" becomes a number, not a claim.

---

## Part 1 — Existing solutions

### 1.0 First, split the problem

Tempest is really two products (see architecture doc, §1). The competitive set
is different for each, and being honest about that matters:

| Tier | What it does | Crowded or novel? |
|------|--------------|-------------------|
| **Tier 2 — content** (Payload Engine: secrets/PII/entropy) | Find secrets in bytes | **Very crowded.** Mature, free, fast incumbents. |
| **Tier 1 — structural** (non-prod code *reaches* prod resource) | Reachability over a code graph | **Sparse.** No mainstream tool ships this exact check out of the box. |

The strategic read: **do not try to out-secret-scan gitleaks.** Tier 1 is the
defensible ground. Tier 2 exists mainly to enrich Tier 1 (see §7.3 of the arch
doc — integrate them).

---

### 1.1 Secret scanners — direct competitors to Tier 2

| Tool | Approach | Strengths | Why it out-competes our Tier 2 today |
|------|----------|-----------|--------------------------------------|
| **Gitleaks** | Regex + entropy over git history & working tree | Fast, ubiquitous, git-history aware, huge default ruleset | Scans *history* not just current files; battle-tested rules |
| **TruffleHog** | Regex + entropy **+ live credential verification** | *Verifies* a found key is actually active (kills false positives) | Verification is a killer feature we don't have |
| **detect-secrets** (Yelp) | Plugin scanners + **baseline file** to suppress known/accepted secrets | Great CI ergonomics, audit workflow | Mature baseline/allowlist workflow |
| **GitGuardian / ggshield** | Commercial, 350+ detectors, dashboard | Broad detector coverage, remediation UX | Enterprise polish, org-wide dashboards |
| **Semgrep Secrets** | Rules + validation | Ties secrets to code context | Backed by Semgrep's engine + rule registry |

**Tempest Tier 2 vs these:** our Payload Engine covers a comparable spread
(P-01…P-08, including notebook cells, VCR cassettes, IDE artifacts — genuinely
nice touches), but it scans only the **current tree**, has **no git-history
scan**, **no live verification**, and **no baseline/allowlist** workflow. On its
own it is a *worse* gitleaks. Its real value only appears once wired to Tier 1.

### 1.2 SAST / taint / data-flow — closest to Tier 1's *mechanism*

| Tool | Approach | Relation to Tempest |
|------|----------|---------------------|
| **CodeQL** (GitHub) | Compiles code to a queryable DB; write taint/dataflow queries | **The real baseline for Tier 1.** You *can* express "non-prod source reaches prod sink" as a CodeQL query — but nobody ships it prebuilt, and it needs a compiled DB + query authoring. Tempest packages the idea. |
| **Semgrep** | Pattern + dataflow (taint mode) | Lighter than CodeQL, multi-language; taint mode could approximate Rule (b)/(c) but you'd hand-write the prod-boundary sources/sinks. |
| **Snyk Code** | ML-assisted SAST | Vuln-focused, not "prod boundary reachability." |
| **SonarQube** | Rules + some dataflow | Quality/security rules, not this specific policy. |

**Key insight:** the *technique* Tempest uses (reachability from boundary nodes)
is a simplified, un-typed cousin of SAST taint analysis. CodeQL/Semgrep do it
more rigorously (real data-flow, not call-edge reachability) but require you to
author the policy. **Tempest's bet is packaging + zero-config + local + agent-native**,
not out-analyzing CodeQL.

### 1.3 Architectural fitness / boundary-rule tools — closest to Tier 1's *intent*

| Tool | Approach | Relation |
|------|----------|----------|
| **ArchUnit** (Java), **import-linter** (Python), **dependency-cruiser** (JS), **Nx module boundaries** | Assert "layer X must not depend on layer Y" over the dependency/import graph | Same *shape* as "non-prod must not reach prod," but these are **rule-authored, language-specific, and about static imports** — not resource-boundary detection or reachability with heuristic PROD tagging. |

Tempest's differentiator here: it **auto-discovers** what's prod vs non-prod and
what a resource boundary is (heuristics + config), rather than making you
declare every layer. That's the moat *and* the risk (heuristics are fuzzy).

### 1.4 Tangential / adjacent

- **DLP & data-lineage** (cloud DLP, OpenLineage, Monte Carlo): runtime/data-plane,
  not source-code static analysis. Different layer.
- **IaC scanners** (Checkov, tfsec, Terrascan): find misconfig in Terraform/K8s,
  a *different* "prod exposure" question.
- **Pre-commit frameworks** (pre-commit, Husky): delivery mechanism, not detectors —
  Tempest could ship as a hook alongside them.

### 1.5 One-line positioning

> Everyone scans *bytes* for secrets (Tier 2 is commoditized). A few
> heavy tools (CodeQL/Semgrep) can *express* reachability if you author it.
> Nobody ships a **zero-config, local, agent-native "can non-prod reach prod"
> check with auto-discovered boundaries** — that's Tempest's whitespace.

---

## Part 2 — How to benchmark ourselves

Benchmarking must be split by tier, because the comparison set and the
"correct answer" are different for each.

### 2.1 What "good" means — metrics

Primary detection metrics, computed **per rule** and **overall**:

| Metric | Definition | Why it matters here |
|--------|------------|---------------------|
| **Precision** | TP / (TP + FP) | FP rate is the #1 thing that gets a security tool uninstalled. |
| **Recall** | TP / (TP + FN) | A leak detector that misses leaks is worthless. |
| **F1 / Fβ** | harmonic mean (β>1 to weight recall) | Single comparable number; use β=2 if you decide misses are worse than noise. |
| **FP rate on clean corpus** | FP per KLOC on leak-free repos | Directly measures "will this annoy people." |

Operational metrics (equally important for an MCP tool an agent calls live):

| Metric | Target to track |
|--------|-----------------|
| Cold sync time (graphify build) | seconds vs repo size (nodes/edges) |
| **Incremental sync time** | should be ≪ cold (note: currently broken — see arch doc P0 #1; benchmark will *prove* the regression) |
| Detect time | seconds vs graph size; scaling curve |
| Peak memory | vs graph size (reachability + all_simple_paths can blow up) |
| MCP round-trip latency | time from tool call → structured result |

### 2.2 Ground-truth datasets — the hard part

You cannot benchmark without labeled data. Build three tiers of corpus:

1. **Synthetic / planted (you already have the seed).**
   `tests/fixtures/leaky_repo/` (one planted leak per rule + clean sibling
   controls) and `clean_repo/` are the nucleus. Expand to a **labeled benchmark
   suite**: N repos, each file/finding annotated `{leak: yes/no, rule, severity}`.
   Cheap, fully controlled, perfect labels — but risks over-fitting to your own
   idea of a leak.

2. **Curated real open-source repos.**
   Pick 20–50 real projects; have 2+ annotators independently label known
   non-prod→prod issues and hardcoded secrets. Measure **inter-annotator
   agreement** (Cohen's κ) so your ground truth is itself trustworthy. This is
   where real-world precision/recall gets measured.

3. **Public secret-scanning benchmarks (Tier 2 only).**
   Reuse existing labeled secret corpora and the incumbents' own test suites so
   Tier 2 numbers are comparable to published gitleaks/TruffleHog results. Do
   **not** invent your own secret set and then claim you beat gitleaks on it.

**Discipline:** freeze a **hold-out set** you never tune on. All heuristic/config
tuning happens on a dev split; final numbers come only from the hold-out. Every
tuning knob (`min_secret_entropy`, `pbn_patterns`, path markers) is a chance to
over-fit.

### 2.3 Comparison baselines — run the competitors on the same corpus

Benchmarking "ourselves" only means something relative to a baseline. For each
tier, run the incumbents on the identical labeled corpus and diff:

- **Tier 2 (content):** Tempest Payload Engine **vs Gitleaks vs TruffleHog vs
  detect-secrets.** Same repos, same ground truth, compare P/R/F1 and FP/KLOC.
  Expect to *lose* on history-awareness and verification — that's fine, it tells
  you exactly what to build or whether to just wrap gitleaks.

- **Tier 1 (structural):** this is the interesting one because there's no
  drop-in competitor. Baselines:
  1. **Hand-authored CodeQL/Semgrep-taint query** encoding "non-prod source →
     prod-boundary sink." This is the *strong* baseline — if a security engineer
     could write this in an afternoon and get better recall, the zero-config
     pitch is the only moat. Measure the gap.
  2. **Naive grep baseline** (does test code import a module named like a prod
     client?) — the *weak* baseline. Tempest must clearly beat this or the graph
     machinery isn't earning its keep.
  3. **Ablations of Tempest itself:** reachability-only vs +relation-filtering vs
     +function-node filtering vs +content-regex classification. Shows which of
     the many guards in `policy.py` actually move the numbers (some may be dead
     weight).

### 2.4 Robustness / stress axes

Beyond accuracy, benchmark the failure modes the code already hints at:

- **Graph-quality sensitivity.** Rule (b)/(c) contain explicit workarounds for
  graphify's backwards edges and spurious 2-node hops. Measure how P/R degrade
  as graphify's AST coverage degrades (different languages/frameworks). This is
  the true ceiling (arch doc §6).
- **Scalability.** Runtime & memory vs graph size on a large monorepo (e.g.
  Kustomize is already in `test_repos/`). `all_simple_paths` with `cutoff=12` is
  the likely blow-up point — chart it.
- **Determinism.** Same repo, same commit → identical findings across runs and
  across OSes (Windows path handling is a known risk area). Flaky findings kill
  trust faster than misses.
- **Language/ecosystem coverage matrix.** P/R broken down by language, since it's
  really graphify's coverage you're measuring.

### 2.5 A concrete harness (build this)

Keep it lazy — a small runner, not a framework:

```
benchmark/
  corpus/
    <repo>/            checked-out repo (or submodule/pin)
    <repo>.labels.json ground truth: [{file, line?, rule, is_leak, severity}]
  run.py               for each repo: tempest_sync + tempest_detect +
                       tempest_scan_content, plus each baseline tool;
                       diff findings vs labels; emit metrics.json
  report.py            aggregate → precision/recall/F1 per rule, per tool,
                       per language; timing + memory; markdown table
```

Rules of the harness:
- **Label format is the contract.** One JSON schema for ground truth; every tool's
  output is normalized to `{file, line, rule/category}` before diffing so
  cross-tool comparison is apples-to-apples.
- **Matching policy is explicit.** Decide up front what counts as a TP (exact
  line? same file+rule? path overlap for reachability findings?) and document it —
  reachability findings match on (source_file, target boundary), not line.
- **Pin everything.** Repo commit SHAs, tool versions, graphify version. A
  benchmark that isn't reproducible is an anecdote.
- **CI job.** Run the synthetic tier on every PR (fast, deterministic); run the
  full corpus nightly. This also finally gives the repo the CI it lacks
  (arch doc P3 #11).

### 2.6 The scoreboard (what a result looks like)

Target deliverable — one table per tier:

```
Tier 1 (structural)        P      R      F1     FP/KLOC   detect(s)
  Tempest (full)          0.xx   0.xx   0.xx    x.x       x.x
  Tempest (reach-only)    ...     ...    ...
  CodeQL hand-query       ...     ...    ...
  grep baseline           ...     ...    ...

Tier 2 (content)           P      R      F1     FP/KLOC   scan(s)
  Tempest Payload          ...
  Gitleaks                 ...
  TruffleHog (+verify)     ...
  detect-secrets           ...
```

The number that matters most for the pitch: **Tier 1 F1 vs the CodeQL hand-query,
at a fraction of the setup cost.** If Tempest gets 80% of CodeQL's recall with
zero query authoring and zero build step, that's the whole story.

---

## Part 3 — TL;DR

- **Tier 2 is a red ocean.** Gitleaks/TruffleHog/detect-secrets are free, fast,
  and ahead of us (history scan, live verification, baselines). Don't compete —
  either wrap one or use Tier 2 only to enrich Tier 1.
- **Tier 1 is open water.** CodeQL/Semgrep can *express* the reachability check
  but nobody ships it zero-config; ArchUnit-style tools do boundary rules but
  require hand-declared layers. Tempest's edge is **auto-discovered boundaries +
  local + agent-native**.
- **Benchmark by tier, against real baselines, on frozen labeled corpora.**
  Compare Tier 2 to gitleaks et al.; compare Tier 1 to a hand-written CodeQL
  query (strong) and grep (weak), plus internal ablations. Report P/R/F1 +
  FP/KLOC + timing, on a pinned, reproducible harness with a hold-out set.
- **Free win:** the benchmark harness will immediately expose the dead
  incremental-sync path (arch doc P0 #1) as a timing regression — first thing it
  should catch.
