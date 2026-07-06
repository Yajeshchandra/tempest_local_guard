# Semantic Enrichment Implementation Plan

## Problem Statement
Currently, Tempest relies entirely on **structural AST edges** (`calls`, `uses`, `instantiates`) extracted by Graphify. 
Because an AST cannot distinguish between a database `read()` and a database `write()`, **Rule B** (Test code writing to Prod) generates false positives if a test simply *reads* from a production database (which is bad practice, but not a destructive data leak).

**Goal:** Annotate or filter graph edges with semantic meaning (`reads_from`, `writes_to`) using an LLM.

---

## Architectural Dilemma: Where does the LLM live?

Tempest is currently a 100% local, offline algorithm. Introducing an LLM requires architectural decisions. We have two main paths:

### Option A: The "Agentic" Approach (Zero-Config)
Since Tempest is an MCP server, it is already being driven by a powerful LLM (Claude, Cursor). 
Instead of Tempest making LLM API calls itself, Tempest simply returns the raw code snippets of the candidate leaks to the Host Agent. 
- **How it works:** Tempest adds a `semantic_verification_prompt` to the output of `tempest_detect`. The Host Agent (Claude) reads the structural finding, looks at the attached code snippet, and uses *its own* reasoning to decide if it's a write operation before showing it to the human.
- **Pros:** No API keys required in Tempest. Zero latency added to the core Python engine. 
- **Cons:** Relies on the Host Agent following instructions perfectly.

### Option B: The "Engine" Approach (Internal LLM Client)
Tempest integrates an LLM client (e.g., `litellm` or `openai`) and makes the API calls itself during the scan.
- **How it works:** During `sync` or `detect`, Tempest grabs the `OPENAI_API_KEY` or local Ollama URL from `.tempest/tempest.config.yaml`. It prompts the LLM: *"Does function X write to resource Y?"*, parses the JSON response, and annotates the graph.
- **Pros:** 100% deterministic outputs from the MCP tool. The graph itself becomes semantically rich for any client to query.
- **Cons:** Requires users to configure API keys for Tempest. Adds network latency (minutes) to the currently lightning-fast (20s) scan.

---

## Processing Pipeline: When do we enrich?

If we choose **Option B** (Internal LLM), we must decide *when* to run the LLM:

1. **RIE Layer (Full Graph Enrichment):** During `tempest_sync`, we find every node that connects to a Production Boundary Node (PBN). We send them all to the LLM to classify as `reads` or `writes`. The resulting `RepositoryIntelligenceModel` (RIM) is permanently enriched.
   - *Cost:* High. A large repo might have 500 connections to the DB.

2. **LDE Layer (Lazy Filter):** During `tempest_detect`, we run the standard structural pathfinding. If we find 3 candidate leaks, we *only* send those 3 specific code snippets to the LLM to verify if they are actually `write` operations. If the LLM says "read", we silently drop the finding.
   - *Cost:* Extremely low (Ponytail approved).

---

## Finalized Plan: Agentic Approach (Zero Config)

Based on the decision to proceed with Option A:
1. Tempest does not make LLM calls itself. No `litellm` or API keys needed.
2. In the final `Report.to_markdown()` output (or directly in the MCP tool response), Tempest will append a system instruction for the Host Agent (Claude).
3. The instruction will ask the Host Agent to evaluate any Rule B findings by looking at the source code context, and only report it to the user if it's a destructive WRITE operation.
4. This keeps the Python engine lightning fast and zero-dependency, leveraging the existing intelligence of the agent driving the MCP server.

## Required Changes
1. **Engine:** Update `lde/report.py` to append the LLM system prompt for Rule B findings.
