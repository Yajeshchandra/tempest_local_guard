"""Runs the full Leak Detection Engine pipeline: load graph -> classify
boundaries -> evaluate policy rules -> build a structured report."""

from __future__ import annotations

import time
from pathlib import Path

from tempest.config import load_config
from tempest.paths import RepoPaths
from tempest.rie.boundary import classify_graph
from tempest.rie.graph_loader import GraphLoadError, load_graph
from tempest.lde.policy import evaluate_all_rules
from tempest.lde.report import Report


class DetectionError(RuntimeError):
    """Raised when detection cannot run (e.g. no synced graph yet)."""


def run_detection(repo_root: str | Path) -> Report:
    """Full pipeline: load the cached graph, classify boundaries, run all 3
    policy rules, and assemble a structured Report. Raises DetectionError if
    `tempest_sync` hasn't been run yet (no graph.json present)."""
    paths = RepoPaths(repo_root)

    if not paths.graph_json.exists():
        raise DetectionError(
            f"No synced graph found at {paths.graph_json}. Run tempest_sync first."
        )

    start = time.monotonic()

    try:
        graph = load_graph(paths.graph_json)
    except GraphLoadError as exc:
        raise DetectionError(str(exc)) from exc

    from tempest.rim import RepositoryIntelligenceModel

    config = load_config(repo_root)
    classifications = classify_graph(graph, config, repo_root)
    
    rim = RepositoryIntelligenceModel(
        graph=graph,
        classifications=classifications,
        config=config,
        repo_root=str(repo_root)
    )
    
    findings: list = evaluate_all_rules(rim)

    from tempest.lde.semantic_filter import apply_semantic_filter
    findings = apply_semantic_filter(findings, rim)

    duration = time.monotonic() - start

    pbn_count = sum(1 for c in classifications.values() if c.is_pbn)
    prod_count = sum(1 for c in classifications.values() if c.is_prod)

    return Report(
        repo_root=str(paths.repo_root),
        findings=findings,
        node_count=graph.number_of_nodes(),
        edge_count=graph.number_of_edges(),
        prod_node_count=prod_count,
        pbn_count=pbn_count,
        duration_seconds=duration,
    )
