"""Reconstructs human-readable evidence paths for a finding."""

from __future__ import annotations

import networkx as nx

from tempest.lde.reachability import reconstruct_paths


def build_path_evidence(
    graph: nx.DiGraph,
    source_id: str,
    target_id: str,
    max_paths: int = 3,
    max_length: int = 12,
) -> list[list[dict]]:
    """Return up to `max_paths` paths from source to target as lists of
    lightweight node summaries (id/label/source_file/source_location),
    suitable for JSON serialization in a Finding."""
    raw_paths = reconstruct_paths(graph, source_id, target_id, max_paths, max_length)

    evidence_paths = []
    for path in raw_paths:
        summarized = []
        for node_id in path:
            data = graph.nodes.get(node_id, {})
            summarized.append(
                {
                    "id": node_id,
                    "label": data.get("label"),
                    "source_file": data.get("source_file"),
                    "source_location": data.get("source_location"),
                }
            )
        evidence_paths.append(summarized)
    return evidence_paths
