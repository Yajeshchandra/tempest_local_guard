"""Selects Production Boundary Nodes (PBNs) and prod-data source nodes from
a classified graph, optionally filtered by pbn_type (database/storage/
messaging/network)."""

from __future__ import annotations

import networkx as nx

from tempest.rie.boundary import NodeClassification


def select_pbns(
    classifications: dict[str, NodeClassification],
    pbn_types: set[str] | None = None,
) -> list[str]:
    """Return PBN node ids, optionally restricted to specific pbn_types
    (e.g. {"database", "storage", "messaging"} for Rule b)."""
    result = []
    for node_id, c in classifications.items():
        if not c.is_pbn:
            continue
        if pbn_types is not None and c.pbn_type not in pbn_types:
            continue
        result.append(node_id)
    return result


def select_prod_data_sources(
    graph: nx.DiGraph,
    classifications: dict[str, NodeClassification],
    sensitive_keywords: list[str],
    pbn_only: bool = False,
) -> list[str]:
    """Prod data sources for Rule (c): PBNs of type database/storage, or any
    PROD node whose label/norm_label matches a sensitive-data keyword (unless
    pbn_only=True, in which case only PBN-typed nodes are returned).

    pbn_only=True is the safer default for Rule (c) to avoid false positives
    from keyword-matched non-PBN prod nodes when graphify creates spurious
    cross-file method edges for same-named methods."""
    result = []
    for node_id, c in classifications.items():
        if not c.is_prod:
            continue
        if c.is_pbn and c.pbn_type in ("database", "storage"):
            result.append(node_id)
            continue
        if pbn_only:
            continue
        label = (graph.nodes[node_id].get("norm_label") or graph.nodes[node_id].get("label") or "").lower()
        if any(kw.lower() in label for kw in sensitive_keywords):
            result.append(node_id)
    return result
