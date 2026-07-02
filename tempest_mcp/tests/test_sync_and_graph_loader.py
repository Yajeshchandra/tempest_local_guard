"""Step 2 verification: graphify subprocess wrapper + graph.json -> DiGraph."""
from __future__ import annotations

import networkx as nx

from tempest.rie.graph_loader import load_graph


def test_sync_produces_graph_json(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    assert result.node_count > 0
    assert result.edge_count > 0
    assert (repo_root / ".tempest" / "graphify-out" / "graph.json").exists()


def test_graph_loader_returns_directed_graph(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph = load_graph(result.graph_json_path)
    assert isinstance(graph, nx.DiGraph)
    assert graph.is_directed()
    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0


def test_graph_contains_expected_planted_nodes(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph = load_graph(result.graph_json_path)
    labels = {data.get("label") for _, data in graph.nodes(data=True)}
    assert "ProdDatabase" in labels
    assert "ProdUserService" in labels
    assert "seed_fake_users()" in labels
    assert "dump_debug_log()" in labels
