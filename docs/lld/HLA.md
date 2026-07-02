# High-Level Architecture

## Local AI-Powered Data Leak Detection System

```mermaid
flowchart TB

    DEV[Developer]

    AGENT["AI Coding Agent<br/>Claude Code / Gemini / ChatGPT / Ollama"]

    subgraph SYSTEM["Local AI-Powered Data Leak Detection System"]

        direction TB

        AIL["Agent Integration Layer (AIL)

Inputs
• MCP Tool Requests

Functions
• Local MCP Server
• Tool Registration
• Request Validation
• Workflow Orchestration
• Request Dispatch
• Result Formatting

Outputs
• Structured Tool Responses"]

        RIE["Repository Intelligence Engine (RIE)

Inputs
• Repository Snapshot
• Repository Delta
• Git Metadata
• Configuration Files
• Build Files
• Repository State

Functions
• Repository State Management
• Incremental Indexing
• Repository Parsing
• Knowledge Graph Construction
• Static Analysis
• Environment Discovery
• Production Boundary Discovery
• Semantic Enrichment
• Repository Intelligence Management

Outputs
Repository Intelligence Model (RIM)
• Detection Graph View
• Production Boundary Index
• Environment Map
• Static Analysis Facts
• Semantic Relationships
• Repository Metadata
• Repository State"]

        LDE["Leak Detection Engine (LDE)

Inputs
• Repository Intelligence Model (RIM)

Functions
• Production Boundary Selection
• Reverse Reachability Analysis
• Path Reconstruction
• Policy Evaluation
• Evidence Generation
• Candidate Leak Detection

Outputs
• Candidate Leak Set
• Complete Leak Paths
• Supporting Evidence
• Policy Violations"]

    end

    RESULT["Candidate Leak Set
Supporting Evidence"]

    REPORT["Developer Analysis

• Ranked Leak Report
• Risk Assessment
• Human Readable Explanation
• Suggested Fixes"]

    DEV -->|"Natural Language Request"| AGENT

    AGENT -->|"MCP Tool Invocation"| AIL

    AIL --> RIE

    RIE -->|"Repository Intelligence Model (RIM)"| LDE

    LDE --> RESULT

    RESULT -->|"Structured Tool Response"| AGENT

    AGENT --> REPORT

    REPORT --> DEV

```

---

# Responsibility Matrix

| Component | Inputs | Core Responsibilities | Outputs |
|-----------|--------|----------------------|----------|
| **Agent Integration Layer (AIL)** | MCP Tool Requests | Local MCP Server, Tool Registration, Workflow Orchestration, Request Dispatch, Result Formatting | Structured Tool Responses |
| **Repository Intelligence Engine (RIE)** | Repository Snapshot, Repository Delta, Git Metadata, Repository State | Build and Maintain Repository Intelligence | Repository Intelligence Model (RIM) |
| **Leak Detection Engine (LDE)** | Repository Intelligence Model (RIM) | Production Boundary Driven Leak Detection, Reverse Reachability Analysis, Path Reconstruction, Policy Evaluation | Candidate Leak Set with Supporting Evidence |
| **AI Coding Agent** *(External)* | Structured Tool Responses | Tool Orchestration, Risk Ranking, Natural Language Explanation, Suggested Fixes | Final Analysis Presented to Developer |

---

# Information Flow

```text
Developer
      │
      ▼
AI Coding Agent
      │
      ▼
Agent Integration Layer
      │
      ▼
Repository Intelligence Engine
      │
      ▼
Repository Intelligence Model (RIM)
      │
      ▼
Leak Detection Engine
      │
      ▼
Candidate Leak Set
      │
      ▼
Structured Tool Response
      │
      ▼
AI Coding Agent
      │
      ▼
Developer
```