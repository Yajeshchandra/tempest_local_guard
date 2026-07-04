"""Diagnostic conftest-style script — run via pytest -s so tempest is importable."""
import sys
from pathlib import Path
import pytest

@pytest.fixture(scope="session")
def _diag(leaky_repo_synced, clean_repo_synced):
    pass

def test_diagnose_rule_b_c(leaky_repo_synced):
    from tempest.rie.graph_loader import load_graph
    from tempest.config import load_config
    from tempest.rie.boundary import classify_graph
    from tempest.lde.pbn_selector import select_pbns, select_prod_data_sources
    from tempest.lde.reachability import ancestors_of_pbn
    from tempest.lde.path_filter import nodes_with_relation_path_to_target
    from tempest.rie.env_map import ENV_TEST
    from tempest.paths import RepoPaths

    repo_root, result = leaky_repo_synced
    paths = RepoPaths(repo_root)
    graph = load_graph(paths.graph_json)
    config = load_config(repo_root)
    classifications = classify_graph(graph, config, repo_root)

    print("\n=== ALL PBNs ===")
    for pid in select_pbns(classifications):
        c = classifications[pid]
        print(f"  {pid}: pbn_type={c.pbn_type}, env={c.env_tag}, reasons={c.reasons}")

    print("\n=== TEST nodes ===")
    for nid, c in classifications.items():
        if c.env_tag == ENV_TEST:
            print(f"  {nid}: {graph.nodes[nid].get('label', '')}")

    db_pbns = select_pbns(classifications, pbn_types={"database", "storage", "messaging"})
    print(f"\n=== DB PBNs: {db_pbns} ===")
    write_rels = set(config.get("write_edge_relations", ["calls", "instantiates", "uses"]))
    for pbn_id in db_pbns:
        reach = ancestors_of_pbn(graph, pbn_id, classifications)
        test_ancs = {nid for nid in reach.ancestors if classifications[nid].env_tag == ENV_TEST}
        print(f"  PBN {pbn_id}: all_ancestors={len(reach.ancestors)}, test_ancestors={test_ancs}")
        if test_ancs:
            matched = nodes_with_relation_path_to_target(graph, test_ancs, pbn_id, write_rels)
            print(f"    relation-matched: {matched}")

    print("\n=== Rule C: prod data sources ===")
    prod_data = select_prod_data_sources(graph, classifications, config.get("sensitive_data_keywords", []))
    print(f"  {prod_data}")
    for pdn in prod_data:
        reach = ancestors_of_pbn(graph, pdn, classifications)
        for nid in reach.ancestors:
            if "clean_debug" in nid:
                label = graph.nodes[nid].get("label", "")
                print(f"  WARNING: clean_debug node '{nid}' ({label}) is ancestor of {pdn}")
                # print path
                import networkx as nx
                try:
                    path = nx.shortest_path(graph, nid, pdn)
                    print(f"    path: {path}")
                except Exception:
                    pass

    print("\n=== All edges involving seed_script ===")
    for u, v, data in graph.edges(data=True):
        if "seed_script" in u or "seed_script" in v:
            print(f"  {u} --[{data.get('relation','?')}]--> {v}")

    print("\n=== All edges involving clean_debug -> user_service ===")
    for u, v, data in graph.edges(data=True):
        if "clean_debug" in u and "user_service" in v:
            print(f"  SPURIOUS: {u} --[{data.get('relation','?')}]--> {v}")

    print("\n=== All edges into user_service_produserservice_get_user_record ===")
    for u, v, data in graph.edges(data=True):
        if v == "user_service_produserservice_get_user_record":
            print(f"  {u} --[{data.get('relation','?')}]--> {v}")

    print("\n=== All edges involving ProdDatabase ===")
    for u, v, data in graph.edges(data=True):
        if "db_proddatabase" in u or "db_proddatabase" in v:
            print(f"  {u} --[{data.get('relation','?')}]--> {v}")
