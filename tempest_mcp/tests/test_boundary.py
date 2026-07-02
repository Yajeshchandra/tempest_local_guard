"""Step 4 verification: PROD/NON-PROD + PBN classification."""
from __future__ import annotations

from tempest.config import load_config
from tempest.rie.boundary import classify_graph
from tempest.rie.graph_loader import load_graph


def _classify(repo_root, result):
    graph = load_graph(result.graph_json_path)
    config = load_config(repo_root)
    return graph, classify_graph(graph, config, repo_root)


def _find_node_id(graph, label, source_file_suffix):
    for node_id, data in graph.nodes(data=True):
        if data.get("label") == label and (data.get("source_file") or "").replace("\\", "/").endswith(
            source_file_suffix
        ):
            return node_id
    raise AssertionError(f"node with label={label!r} suffix={source_file_suffix!r} not found")


def test_prod_folder_classified_prod(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "ProdDatabase", "prod/db.py")
    assert classifications[node_id].is_prod


def test_prod_database_is_pbn_with_correct_type(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "ProdDatabase", "prod/db.py")
    c = classifications[node_id]
    assert c.is_pbn
    assert c.pbn_type == "database"


def test_dev_folder_classified_dev_not_prod(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "LocalDatabase", "dev/local_db.py")
    c = classifications[node_id]
    assert not c.is_prod
    assert c.env_tag == "DEV"


def test_tests_folder_classified_test(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "seed_fake_users()", "tests/seed_script.py")
    c = classifications[node_id]
    assert not c.is_prod
    assert c.env_tag == "TEST"


def test_nested_repo_path_does_not_leak_ancestor_folder_names(leaky_repo_synced):
    """Regression test: the fixture repo lives under .../tempest_mcp/tests/
    fixtures/leaky_repo/, so a naive absolute-path folder-marker match would
    misclassify everything under dev/ as TEST because of the ancestor
    'tests' segment. Classification must be relative to repo_root."""
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "dump_debug_log()", "dev/debug_utils.py")
    c = classifications[node_id]
    assert c.env_tag == "DEV", f"expected DEV, got {c.env_tag} (reasons: {c.reasons})"


def test_docstring_mentioning_prod_hostname_does_not_flip_whole_file_to_prod(leaky_repo_synced):
    """Regression test: prod_identifier_patterns must only fire on genuine
    string-literal content, and only when the path heuristic found no
    signal at all -- never overriding an explicit TEST/DEV folder tag just
    because a comment/docstring mentions a prod-looking hostname."""
    repo_root, result = leaky_repo_synced
    graph, classifications = _classify(repo_root, result)
    node_id = _find_node_id(graph, "debug_utils.py", "dev/debug_utils.py")
    c = classifications[node_id]
    assert not c.is_prod
    assert c.env_tag == "DEV"


def test_unmatched_node_defaults_non_prod():
    from tempest.rie.env_map import classify_env_for_path, ENV_UNKNOWN

    config = {"boundary": {}}
    assert classify_env_for_path(None, config) == ENV_UNKNOWN
    assert classify_env_for_path("somewhere/unclassified.py", config) == ENV_UNKNOWN
