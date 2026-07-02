"""Filters reachability candidates down to genuine rule matches.

`nx.ancestors` gives *every* node that can reach a PBN transitively — that's
too broad to report directly (e.g. a module that merely imports another
module which eventually imports the PBN). Each rule narrows this using its
own structural/content criteria; this module holds shared filtering helpers.
"""

from __future__ import annotations

import networkx as nx


def has_direct_or_transitive_edge_of_relations(
    graph: nx.DiGraph,
    source_id: str,
    target_id: str,
    relations: set[str],
    max_depth: int = 12,
) -> bool:
    """True if there is a path from source_id to target_id where every edge
    on the path has a `relation` in `relations`. Used by Rule (b) to
    distinguish "calls/instantiates/uses" chains (approximating a write)
    from purely structural chains (e.g. `contains`/`imports_from` only).
    """
    if source_id not in graph or target_id not in graph:
        return False

    # BFS over a relation-filtered view of the graph.
    visited = {source_id}
    frontier = [source_id]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        for node in frontier:
            for _, nbr, data in graph.out_edges(node, data=True):
                if data.get("relation") not in relations:
                    continue
                if nbr == target_id:
                    return True
                if nbr not in visited:
                    visited.add(nbr)
                    next_frontier.append(nbr)
        frontier = next_frontier
        depth += 1
    return False


def nodes_with_relation_path_to_target(
    graph: nx.DiGraph,
    candidate_ids: set[str],
    target_id: str,
    relations: set[str],
    max_depth: int = 12,
) -> set[str]:
    """Restrict `candidate_ids` to those with a relation-filtered path to
    `target_id`. Runs a single reverse BFS from target_id over edges whose
    relation is in `relations`, which is far cheaper than testing each
    candidate individually."""
    if target_id not in graph:
        return set()

    reverse_reachable: set[str] = set()
    frontier = [target_id]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        for node in frontier:
            for pred, _, data in graph.in_edges(node, data=True):
                if data.get("relation") not in relations:
                    continue
                if pred not in reverse_reachable:
                    reverse_reachable.add(pred)
                    next_frontier.append(pred)
        frontier = next_frontier
        depth += 1

    return candidate_ids & reverse_reachable
