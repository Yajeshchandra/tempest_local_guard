"""Reverse reachability core.

For each Production Boundary Node (PBN) `p`, `networkx.ancestors(G, p)` gives
every node with a directed path to `p` — this *is* the reverse traversal, no
need to hand-build a reversed graph. We then filter out PROD->PROD
reachability (not a leak; prod code calling prod resources is expected) and
dedupe across multiple PBNs before handing candidates to the policy rules.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from tempest.rie.boundary import NodeClassification


@dataclass
class ReachabilityResult:
    pbn_id: str
    ancestors: set[str]  # non-prod ancestor node ids only


def ancestors_of_pbn(
    graph: nx.DiGraph,
    pbn_id: str,
    classifications: dict[str, NodeClassification],
) -> ReachabilityResult:
    """All non-prod nodes with a directed path to the given PBN.

    PROD->PROD reachability is filtered out here: a prod node calling
    another prod resource is expected behavior, not a leak candidate.
    """
    if pbn_id not in graph:
        return ReachabilityResult(pbn_id=pbn_id, ancestors=set())

    all_ancestors = nx.ancestors(graph, pbn_id)

    non_prod_ancestors = {
        nid
        for nid in all_ancestors
        if not classifications.get(nid, _unknown_classification(nid)).is_prod
    }
    return ReachabilityResult(pbn_id=pbn_id, ancestors=non_prod_ancestors)


def _unknown_classification(node_id: str) -> NodeClassification:
    # Nodes missing from the classification map (shouldn't normally happen,
    # since classify_graph covers every node) are treated as NON-PROD — the
    # same safe default used throughout boundary classification.
    return NodeClassification(
        node_id=node_id,
        env_tag="NON_PROD",
        is_prod=False,
        is_pbn=False,
        pbn_type=None,
        reasons=["missing classification; defaulted NON-PROD"],
    )


def all_pbn_reachability(
    graph: nx.DiGraph,
    pbn_ids: list[str],
    classifications: dict[str, NodeClassification],
) -> dict[str, ReachabilityResult]:
    """Compute non-prod ancestor sets for every PBN in one pass."""
    return {
        pbn_id: ancestors_of_pbn(graph, pbn_id, classifications) for pbn_id in pbn_ids
    }


def reconstruct_paths(
    graph: nx.DiGraph,
    source_id: str,
    target_id: str,
    max_paths: int = 3,
    max_length: int = 12,
) -> list[list[str]]:
    """Reconstruct up to `max_paths` simple paths from source to target, for
    evidence. Capped since simple-path enumeration is exponential in dense
    graphs. Falls back to the single shortest path if enumeration yields
    nothing (e.g. max_length too small) but a path is known to exist.
    """
    paths: list[list[str]] = []
    try:
        for path in nx.all_simple_paths(graph, source_id, target_id, cutoff=max_length):
            paths.append(path)
            if len(paths) >= max_paths:
                break
    except (nx.NodeNotFound, nx.NetworkXNoPath):
        return []

    if not paths:
        try:
            paths = [nx.shortest_path(graph, source_id, target_id)]
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return []

    return paths
