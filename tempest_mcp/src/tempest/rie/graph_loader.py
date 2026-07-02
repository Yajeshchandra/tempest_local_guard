"""Loads graphify's graph.json (NetworkX node-link JSON) into a networkx.DiGraph.

IMPORTANT: graphify's graph.json includes an explicit top-level `"directed"`
field. Empirically this is `false` for plain AST-only extractions (no
semantic/LLM pass), even though the edge relations themselves (`calls`,
`imports`, `contains`, ...) are inherently directional. `networkx.node_link_graph`
only honors its `directed=` keyword argument as a fallback for when the field
is *absent* from the data — an explicit `false` in the JSON always wins over
the keyword argument. Since Tempest's reachability engine fundamentally
requires directed edges, we force directedness ourselves by overwriting the
`directed` field in the parsed dict before handing it to networkx, rather
than relying on the `directed=True` keyword alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
from networkx.readwrite.json_graph import node_link_graph


class GraphLoadError(RuntimeError):
    """Raised when graph.json is missing, malformed, or empty."""


def load_graph(graph_json_path: str | Path) -> nx.DiGraph:
    """Load a graphify graph.json file into a networkx.DiGraph.

    Edges are read from the `links` array (graphify's node-link format uses
    `links`, not the newer `edges` key).
    """
    graph_json_path = Path(graph_json_path)
    if not graph_json_path.exists():
        raise GraphLoadError(f"graph.json not found at {graph_json_path}")

    try:
        with open(graph_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise GraphLoadError(f"graph.json at {graph_json_path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "nodes" not in data:
        raise GraphLoadError(f"graph.json at {graph_json_path} is missing a 'nodes' array")

    # Force directed regardless of what the source file recorded — see
    # module docstring for why the `directed=` kwarg alone isn't enough.
    data = dict(data)
    data["directed"] = True

    edges_key = "links" if "links" in data else "edges"

    graph = node_link_graph(data, edges=edges_key, multigraph=False)

    if not isinstance(graph, nx.DiGraph):
        # Belt-and-braces: should be unreachable given the forced `directed`
        # field above, but guarantees callers always get a DiGraph.
        graph = nx.DiGraph(graph)

    return graph


def load_graph_for_repo(repo_root: str | Path) -> nx.DiGraph:
    """Convenience wrapper: resolve the repo's .tempest/graph.json and load it."""
    from tempest.paths import RepoPaths

    paths = RepoPaths(repo_root)
    return load_graph(paths.graph_json)
