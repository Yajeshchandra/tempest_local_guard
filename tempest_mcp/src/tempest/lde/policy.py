"""The 3 Tempest policy rules. Each is an independent, unit-testable function
taking the shared graph + classification data and returning Finding objects.

  (a) hardcoded prod secrets in non-prod code
  (b) test/seed code writing to a prod resource
  (c) prod data reaching non-prod logging/debug sinks
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import networkx as nx

from tempest.lde.evidence import Finding, summarize_node
from tempest.lde.path_filter import (
    has_direct_or_transitive_edge_of_relations,
    nodes_with_relation_path_to_target,
)
from tempest.lde.path_reconstruct import build_path_evidence
from tempest.lde.pbn_selector import select_pbns, select_prod_data_sources
from tempest.lde.reachability import ancestors_of_pbn
from tempest.rie.boundary import NodeClassification
from tempest.rie.env_map import ENV_TEST, NONPROD_LEAK_ENVS
from tempest.rim import RepositoryIntelligenceModel


def _confidence_from_reasons(reasons: list[str]) -> str:
    """How strong is the signal that this source is non-prod code?
      high   — framework import (pytest/faker/...): near-unambiguous test/dev code
      medium — folder or filename convention (tests/, test_*, seed*, scripts/)
      low    — anything weaker (kept for completeness)
    """
    joined = " ".join(reasons).lower()
    if "nonprod_import" in joined:
        return "high"
    if "path heuristic" in joined:  # folder or filename marker
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Rule (b) — test/seed code writing to a prod resource.
# ---------------------------------------------------------------------------
def evaluate_rule_b(
    rim: RepositoryIntelligenceModel,
    max_paths: int = 3,
    max_path_length: int = 12,
) -> list[Finding]:
    """Candidates: nodes tagged specifically TEST that reach a PBN of
    boundary_type database/storage/messaging via a calls/instantiates/uses
    edge. graphify has no explicit write-edge type, so this is an
    approximation over call/use edges — documented as a known MVP
    limitation (a read-only call into a PBN would also match).
    """
    graph, classifications, config = rim.graph, rim.classifications, rim.config
    write_relations = set(config.get("write_edge_relations", ["calls", "instantiates", "uses"]))
    pbn_types = {"database", "storage", "messaging"}
    # Sink-labeled non-prod code (log/debug/dump) reaching prod is Rule (c)'s
    # domain — skip it here so one leak isn't double-reported under both rules.
    sink_patterns = [p.lower() for p in config.get("sink_patterns", [])]

    pbns = select_pbns(classifications, pbn_types=pbn_types)
    findings: list[Finding] = []

    for pbn_id in pbns:
        reach = ancestors_of_pbn(graph, pbn_id, classifications)
        test_ancestors = {
            nid for nid in reach.ancestors
            if classifications[nid].env_tag in NONPROD_LEAK_ENVS
        }

        # Graphify sometimes emits edges in the wrong direction (PBN→test instead
        # of test→PBN). Also check non-prod descendants of the PBN to catch both.
        test_descendants = {
            nid
            for nid in nx.descendants(graph, pbn_id)
            if nid in classifications and classifications[nid].env_tag in NONPROD_LEAK_ENVS
        }

        test_candidates = test_ancestors | test_descendants
        if not test_candidates:
            continue

        # Narrow to ancestors connected via a write-relevant relation chain,
        # not merely structural containment/imports.
        matched_anc = nodes_with_relation_path_to_target(
            graph, test_ancestors, pbn_id, write_relations, max_depth=max_path_length
        ) if test_ancestors else set()

        # For descendants: check relation-filtered path FROM pbn to the test node
        # (inverted edge scenario — the PBN has a calls edge into test code).
        matched_desc = {
            nid for nid in test_descendants
            if has_direct_or_transitive_edge_of_relations(graph, pbn_id, nid, write_relations, max_path_length)
        }

        matched = matched_anc | matched_desc

        for source_id in matched:
            # Only report function/method-level nodes as sources — not module
            # containers, imports, or rationale (docstring) nodes.
            src_data = graph.nodes.get(source_id, {})
            src_label = src_data.get("label") or ""
            if not (src_data.get("source_location") and src_label.endswith("()")):
                continue
            src_label_l = (src_data.get("norm_label") or src_label).lower()
            if any(p in src_label_l for p in sink_patterns):
                continue  # sink-labeled → Rule (c), not Rule (b)
            # Skip the module that DEFINES the resource client — that's the
            # boundary itself, not non-prod code reaching it.
            if src_data.get("source_file") and src_data.get("source_file") == graph.nodes.get(pbn_id, {}).get("source_file"):
                continue
            paths = build_path_evidence(graph, source_id, pbn_id, max_paths, max_path_length)
            # For inverted edges, paths may be empty (source→PBN doesn't exist).
            # Build a reverse path instead.
            if not paths:
                paths = build_path_evidence(graph, pbn_id, source_id, max_paths, max_path_length)
            pbn_type = classifications[pbn_id].pbn_type
            findings.append(
                Finding(
                    rule="b",
                    rule_name="non_prod_code_reaches_prod_resource",
                    severity="high",
                    confidence=_confidence_from_reasons(classifications[source_id].reasons),
                    source_node=summarize_node(graph, source_id),
                    target_node=summarize_node(graph, pbn_id),
                    paths=paths,
                    evidence={
                        "pbn_type": pbn_type,
                        "matched_relations": sorted(write_relations),
                        "source_env": classifications[source_id].env_tag,
                        "why_non_prod": classifications[source_id].reasons,
                    },
                    suggested_fix=(
                        "Point this test/seed code at a local or test-environment "
                        f"{pbn_type or 'resource'} instead of the production instance. "
                        "Consider injecting the resource client via config/DI so tests "
                        "can never construct a prod client directly."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Rule (c) — prod data reaching non-prod logging/debug sinks.
# ---------------------------------------------------------------------------
def evaluate_rule_c(
    rim: RepositoryIntelligenceModel,
    max_paths: int = 3,
    max_path_length: int = 12,
) -> list[Finding]:
    """Reuses the reachability engine with source/target sets swapped:
    prod_data_nodes (PBNs of type database/storage, or PROD nodes matching
    sensitive-data keywords) play the PBN role, and we look for non-prod
    sink-labeled (log/debug/dump) ancestors of them.
    """
    graph, classifications, config = rim.graph, rim.classifications, rim.config
    sensitive_keywords = config.get("sensitive_data_keywords", [])
    sink_patterns = [p.lower() for p in config.get("sink_patterns", [])]

    prod_data_nodes = select_prod_data_sources(
        graph, classifications, sensitive_keywords
    )
    # ponytail: rationale nodes are prose sentences (label ends with '.'); skip them.
    # Also skip method nodes (label starts with '.') — class is the right target granularity.
    prod_data_nodes = [
        nid for nid in prod_data_nodes
        if not (graph.nodes[nid].get("label") or "").endswith(".")
        and not (graph.nodes[nid].get("label") or "").startswith(".")
    ]
    # Prefer the most specific (deepest / most sensitive) prod-data nodes:
    # if a database/storage PBN and a sensitive-keyword node are on the same
    # ancestry chain (e.g. ProdDatabase <- ProdUserService.get_user_record),
    # only the PBN is kept as the target so we don't emit one finding per
    # node along a single real leak.
    prod_data_nodes = _dedupe_prod_data_nodes(graph, prod_data_nodes)

    # A "sink" must be an actual function/method-level node (has a concrete
    # source_location and a call-shaped label), not a module/file container
    # or a docstring rationale node -- those would otherwise multiply
    # findings for what is really one leak.
    def _is_function_like(node_id: str) -> bool:
        data = graph.nodes.get(node_id, {})
        label = data.get("label") or ""
        return bool(data.get("source_location")) and label.endswith("()")

    findings: list[Finding] = []
    # Dedupe by (sink_id) across multiple prod_data targets: report each
    # sink function once, evidenced by its shortest/most direct prod-data
    # reach rather than once per matched prod-data node.
    best_finding_for_sink: dict[str, tuple[str, list]] = {}

    for data_node_id in prod_data_nodes:
        reach = ancestors_of_pbn(graph, data_node_id, classifications)

        for nid in reach.ancestors:
            if not _is_function_like(nid):
                continue
            data = graph.nodes.get(nid, {})
            label = (data.get("norm_label") or data.get("label") or "").lower()
            if not any(pattern in label for pattern in sink_patterns):
                continue

            if nid in best_finding_for_sink:
                continue  # already have a finding for this sink function

            # A genuine Rule (c) violation requires the sink to directly reach
            # a prod-classified node as its FIRST callee — and that first hop
            # must be an intermediate (not the data_node itself). Spurious
            # graphify edges are always 2-node direct hops (sink → target);
            # real leaks go through at least one prod class/method first.
            direct_prod_reach = False
            try:
                for path in nx.all_simple_paths(graph, nid, data_node_id, cutoff=12):
                    if len(path) >= 2:  # ponytail: method targets excluded, 2-hop to class is genuine
                        first_hop = path[1]
                        if classifications.get(first_hop) and classifications[first_hop].is_prod:
                            direct_prod_reach = True
                            break
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                pass

            if not direct_prod_reach:
                continue

            paths = build_path_evidence(graph, nid, data_node_id, max_paths, max_path_length)
            best_finding_for_sink[nid] = (data_node_id, paths)

    for sink_id, (data_node_id, paths) in best_finding_for_sink.items():
        findings.append(
            Finding(
                rule="c",
                rule_name="prod_data_reaches_non_prod_sink",
                severity="high",
                source_node=summarize_node(graph, sink_id),
                target_node=summarize_node(graph, data_node_id),
                paths=paths,
                evidence={
                    "sink_match": True,
                },
                suggested_fix=(
                    "Avoid logging/dumping real production data from non-prod code. "
                    "Redact or mock sensitive fields before logging, or point this "
                    "debug path at a non-prod data source."
                ),
            )
        )

    return findings


def _dedupe_prod_data_nodes(graph: nx.DiGraph, prod_data_nodes: list[str]) -> list[str]:
    """Drop prod-data nodes that are ancestors of another selected prod-data
    node (e.g. a sensitive-keyword function that itself calls into a
    database PBN) so Rule (c) reports one finding per real leak rather than
    one per node along the same chain."""
    node_set = set(prod_data_nodes)
    keep = []
    for node_id in prod_data_nodes:
        descendants_in_set = False
        try:
            for other in node_set:
                if other == node_id:
                    continue
                if nx.has_path(graph, node_id, other):
                    descendants_in_set = True
                    break
        except nx.NodeNotFound:
            pass
        if not descendants_in_set:
            keep.append(node_id)
    return keep or prod_data_nodes


# ---------------------------------------------------------------------------
# Rule (a) — hardcoded prod secrets in non-prod code.
# ---------------------------------------------------------------------------
_STRING_LITERAL_RE = re.compile(r"""(['"])((?:(?!\1).)*)\1""")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    import math

    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _iter_non_prod_source_files(
    graph: nx.DiGraph, classifications: dict[str, NodeClassification]
) -> set[str]:
    """Distinct source_file paths belonging to non-prod-classified nodes."""
    files = set()
    for node_id, data in graph.nodes(data=True):
        c = classifications.get(node_id)
        if c is None or c.is_prod:
            continue
        source_file = data.get("source_file")
        if source_file:
            files.add(source_file)
    return files


def evaluate_rule_a(
    rim: RepositoryIntelligenceModel,
) -> list[Finding]:
    """Mostly a classification-informed grep, not a traversal: scans every
    non-prod source file's string literals for known_prod_identifiers or
    prod_identifier_patterns/entropy matches.
    """
    graph, classifications, config, repo_root = rim.graph, rim.classifications, rim.config, rim.repo_root
    
    findings: list[Finding] = []
    repo_root = Path(repo_root)
    boundary_cfg = config.get("boundary", {})
    patterns = [re.compile(p, re.IGNORECASE) for p in boundary_cfg.get("prod_identifier_patterns", [])]
    secret_patterns = [re.compile(p, re.IGNORECASE) for p in config.get("secret_patterns", {}).values()]
    known_identifiers = [k.lower() for k in config.get("known_prod_identifiers", [])]
    min_entropy = boundary_cfg.get("min_secret_entropy", 3.0)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # (source_file, literal) dedup

    non_prod_files = _iter_non_prod_source_files(graph, classifications)

    # Map source_file -> a representative non-prod node id (for reporting).
    file_to_node: dict[str, str] = {}
    for node_id, data in graph.nodes(data=True):
        c = classifications.get(node_id)
        if c is None or c.is_prod:
            continue
        sf = data.get("source_file")
        if sf and sf not in file_to_node:
            file_to_node[sf] = node_id

    for source_file in non_prod_files:
        path = Path(source_file)
        if not path.is_absolute():
            path = repo_root / source_file
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for match in _STRING_LITERAL_RE.finditer(text):
            literal = match.group(2)
            if not literal or len(literal) < 6:
                continue

            key = (source_file, literal)
            if key in seen:
                continue

            matched_pattern = any(p.search(literal) for p in patterns)
            matched_known = any(k in literal.lower() for k in known_identifiers)
            matched_secret = any(p.search(literal) for p in secret_patterns)
            is_secret_like = _shannon_entropy(literal) >= min_entropy and any(
                c.isdigit() for c in literal
            ) and any(c.isalpha() for c in literal)

            if not (matched_pattern or matched_known or matched_secret):
                continue
            # Require the literal to also look secret/identifier-like (not
            # just any string that happens to contain "prod") OR to be a
            # connection-string-shaped match, OR to be a direct secret hit.
            looks_like_connection_or_key = bool(
                re.search(r"://|@|sk_live|api[_-]?key|secret|password|token", literal, re.IGNORECASE)
            )
            if not (matched_known or matched_secret or looks_like_connection_or_key or is_secret_like):
                continue

            seen.add(key)
            node_id = file_to_node.get(source_file)
            source_summary = (
                summarize_node(graph, node_id)
                if node_id
                else {"id": None, "label": None, "source_file": source_file, "source_location": None}
            )

            findings.append(
                Finding(
                    rule="a",
                    rule_name="hardcoded_prod_secret_in_non_prod_code",
                    severity="high",
                    source_node=source_summary,
                    target_node=None,
                    paths=[],
                    evidence={
                        "matched_literal": literal,
                        "matched_known_identifier": matched_known,
                        "matched_pattern": matched_pattern,
                        "matched_secret_pattern": matched_secret,
                        "entropy": round(_shannon_entropy(literal), 2),
                    },
                    suggested_fix=(
                        "Remove this hardcoded production identifier/credential from "
                        "non-prod code. Load it from a secrets manager or environment "
                        "variable scoped to prod deploys only, and rotate the credential "
                        "since it has been committed to a non-prod-visible file."
                    ),
                )
            )

    return findings


def evaluate_all_rules(
    rim: RepositoryIntelligenceModel,
) -> list[Finding]:
    max_paths = rim.config.get("max_paths_per_finding", 3)
    max_path_length = rim.config.get("max_path_length", 12)

    findings: list[Finding] = []
    findings.extend(evaluate_rule_a(rim))
    findings.extend(evaluate_rule_b(rim, max_paths, max_path_length))
    findings.extend(evaluate_rule_c(rim, max_paths, max_path_length))
    return findings
