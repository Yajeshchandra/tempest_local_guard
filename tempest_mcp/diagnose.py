from pathlib import Path
from tempest.rie.graph_loader import load_graph
from tempest.config import load_config
from tempest.rie.boundary import classify_graph
from tempest.lde.pbn_selector import select_pbns, select_prod_data_sources
from tempest.lde.reachability import ancestors_of_pbn
from tempest.lde.path_filter import nodes_with_relation_path_to_target
from tempest.rie.env_map import ENV_TEST

repo = Path("tests/fixtures/leaky_repo")
graph = load_graph(repo / ".tempest" / "graph.json")
config = load_config(repo)
classifications = classify_graph(graph, config, repo)

# Show PBNs
pbns = select_pbns(classifications)
print("=== ALL PBNs ===")
for pid in pbns:
    c = classifications[pid]
    print(f"  {pid}: pbn_type={c.pbn_type}, env={c.env_tag}")

# Show TEST nodes
print("\n=== TEST nodes ===")
for nid, c in classifications.items():
    if c.env_tag == ENV_TEST:
        label = graph.nodes[nid].get("label", "")
        print(f"  {nid}: {label}")

# Rule B: check ancestors of database PBNs
print("\n=== Rule B: DB PBNs ===")
db_pbns = select_pbns(classifications, pbn_types={"database", "storage", "messaging"})
print(f"DB PBNs: {db_pbns}")

write_relations = set(config.get("write_edge_relations", ["calls", "instantiates", "uses"]))
for pbn_id in db_pbns:
    reach = ancestors_of_pbn(graph, pbn_id, classifications)
    test_ancs = {nid for nid in reach.ancestors if classifications[nid].env_tag == ENV_TEST}
    print(f"  PBN {pbn_id}: test_ancestors={test_ancs}")
    if test_ancs:
        matched = nodes_with_relation_path_to_target(graph, test_ancs, pbn_id, write_relations)
        print(f"    -> relation-matched: {matched}")

# Rule C: check clean_debug_utils classification and ancestors
print("\n=== Rule C: clean_debug_utils ===")
for nid, data in graph.nodes(data=True):
    if "clean_debug" in nid:
        c = classifications.get(nid)
        print(f"  node={nid}, env={c.env_tag if c else 'NO_CLASS'}, is_prod={c.is_prod if c else '?'}")
        
prod_data = select_prod_data_sources(graph, classifications, config.get("sensitive_data_keywords", []))
print(f"\nProd data sources: {prod_data}")

# Check if clean_debug_utils is an ancestor of any prod data node
for pdn in prod_data:
    reach = ancestors_of_pbn(graph, pdn, classifications)
    for nid in reach.ancestors:
        if "clean_debug" in nid:
            print(f"  clean_debug_utils IS an ancestor of {pdn}")
