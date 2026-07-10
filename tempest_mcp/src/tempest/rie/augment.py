"""AST augmentation: injects synthetic PBN nodes for third-party resource-
client calls (boto3.client, psycopg2.connect, a celery broker repoint, ...)
that graphify's own graph never emits — it models local function/class
structure, not third-party call expressions. Without this, Rule (b)/(c)
structural traversal has nothing to reach for leaks that go through an
inline driver/SDK call instead of a shared prod module.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import networkx as nx

from tempest.rie.env_map import ENV_DEV, ENV_TEST, classify_env_for_path


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


class _ResourceCallCollector(ast.NodeVisitor):
    """Collects (enclosing_func_lineno, site_lineno, dotted_text) for every
    Call and Attribute-assignment target in the file, tagged with the
    nearest enclosing function's def line (None at module level)."""

    def __init__(self) -> None:
        self.func_stack: list[int] = []
        self.matches: list[tuple[int | None, int, str]] = []

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func_stack.append(node.lineno)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        if dotted:
            enclosing = self.func_stack[-1] if self.func_stack else None
            self.matches.append((enclosing, node.lineno, dotted))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute):
            dotted = _dotted(node.targets[0])
            if dotted:
                enclosing = self.func_stack[-1] if self.func_stack else None
                self.matches.append((enclosing, node.lineno, dotted))
        self.generic_visit(node)


def _match_resource_client(
    dotted: str, resource_client_patterns: dict[str, list[str]]
) -> str | None:
    low = dotted.lower()
    for pbn_type, patterns in resource_client_patterns.items():
        for pat in patterns:
            if pat.lower() in low:
                return pbn_type
    return None


def augment_graph_with_ast(
    graph: nx.DiGraph, repo_root: str | Path, config: dict[str, Any]
) -> nx.DiGraph:
    """Scan every .py source file already present in the graph for resource-
    client call/assignment sites graphify didn't emit nodes for, and add a
    synthetic PBN-candidate node + a `calls` edge from the enclosing function
    node. Mutates and returns `graph`.

    Synthetic nodes are marked `_synthetic: True` — `classify_node` only
    promotes a DEV/TEST-file resource-client node to PBN (and prod) status
    for synthetic nodes with a co-located prod identifier, so this pass alone
    can't turn an ordinary graphify node into a false PBN.
    """
    resource_client_patterns = config.get("resource_client_patterns", {})
    if not resource_client_patterns:
        return graph

    repo_root = Path(repo_root)

    # source_file -> {def_lineno: function_node_id}, from existing nodes.
    func_nodes_by_file: dict[str, dict[int, str]] = {}
    py_files: set[str] = set()
    for node_id, data in graph.nodes(data=True):
        sf = data.get("source_file")
        if not sf:
            continue
        if sf.endswith(".py"):
            py_files.add(sf)
        label = data.get("label") or ""
        loc = data.get("source_location") or ""
        if label.endswith("()") and loc.startswith("L"):
            try:
                lineno = int(loc[1:])
            except ValueError:
                continue
            func_nodes_by_file.setdefault(sf, {})[lineno] = node_id

    seen: set[tuple[str, str]] = set()  # (source_file, dotted) dedup

    for source_file in py_files:
        # Only augment files that are ALREADY path-heuristic DEV/TEST — that's
        # the only case Rule (b)/(c) need synthetic help for (a non-prod
        # script/test embedding a real client inline). Real prod app files
        # (e.g. app/db/events.py) already get correct PBN status from
        # graphify's own nodes when relevant; augmenting them too would add a
        # synthetic node under a legitimate startup/lifecycle call and turn a
        # documented clean control into a false positive.
        if classify_env_for_path(source_file, config) not in (ENV_DEV, ENV_TEST):
            continue

        path = Path(source_file)
        if not path.is_absolute():
            path = repo_root / source_file
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue

        collector = _ResourceCallCollector()
        collector.visit(tree)

        func_lines = func_nodes_by_file.get(source_file, {})
        for enclosing_lineno, site_lineno, dotted in collector.matches:
            if enclosing_lineno is None:
                continue  # module-level site, no function node to anchor to
            func_node_id = func_lines.get(enclosing_lineno)
            if not func_node_id:
                continue

            pbn_type = _match_resource_client(dotted, resource_client_patterns)
            if not pbn_type:
                continue

            key = (source_file, dotted)
            if key in seen:
                continue
            seen.add(key)

            synthetic_id = f"{func_node_id}::synthetic_pbn::{pbn_type}::{site_lineno}"
            graph.add_node(
                synthetic_id,
                label=f"{dotted}()",
                file_type="code",
                source_file=source_file,
                source_location=f"L{site_lineno}",
                _synthetic=True,
            )
            graph.add_edge(func_node_id, synthetic_id, relation="calls")

    return graph


# ---------------------------------------------------------------------------
# Multi-language regex augmentation (Phase 3).
# ---------------------------------------------------------------------------
_NONPY_SOURCE_SUFFIXES = (
    ".cs", ".go", ".java", ".js", ".ts", ".php", ".rb", ".kt", ".scala", ".cpp",
)


def augment_graph_multilang(
    graph: nx.DiGraph, repo_root: str | Path, config: dict[str, Any]
) -> nx.DiGraph:
    """Recognize DB/cache/queue clients in NON-Python source via regex, since
    graphify labels the access class after the app (CatalogContext,
    RedisCartStore), not the client library — so `resource_client_patterns`
    substring matching misses them. For each `resource_client_regexes` match in
    a non-Python file, anchor a synthetic PBN node (of the matched type) to the
    nearest enclosing code node (class/function) by line, so Rules (b)/(c) and
    boundary classification see the resource boundary. One synthetic node per
    (file, type). Mutates and returns `graph`.

    Synthetic nodes carry `_synthetic` + `_pbn_type`; `classify_node` still
    applies the DEV/TEST co-located-prod-identifier gate, so a test double
    (FakeRedis in a test file with no prod id) stays non-PBN.
    """
    regex_cfg = config.get("resource_client_regexes", {})
    if not regex_cfg:
        return graph
    compiled: dict[str, list[re.Pattern]] = {
        pbn_type: [re.compile(p) for p in pats]
        for pbn_type, pats in regex_cfg.items()
    }

    repo_root = Path(repo_root)

    # source_file -> sorted [(lineno, node_id)] for every code node with a line,
    # plus a representative fallback node id for the file.
    code_lines_by_file: dict[str, list[tuple[int, str]]] = {}
    file_fallback: dict[str, str] = {}
    nonpy_files: set[str] = set()
    for node_id, data in graph.nodes(data=True):
        sf = data.get("source_file")
        if not sf:
            continue
        if sf.lower().endswith(_NONPY_SOURCE_SUFFIXES):
            nonpy_files.add(sf)
        file_fallback.setdefault(sf, node_id)
        loc = data.get("source_location") or ""
        if loc.startswith("L"):
            try:
                code_lines_by_file.setdefault(sf, []).append((int(loc[1:]), node_id))
            except ValueError:
                continue
    for sf in code_lines_by_file:
        code_lines_by_file[sf].sort()

    def _anchor(source_file: str, line: int) -> str:
        best = None
        for ln, nid in code_lines_by_file.get(source_file, []):
            if ln <= line:
                best = nid
            else:
                break
        return best or file_fallback[source_file]

    for source_file in nonpy_files:
        path = Path(source_file)
        if not path.is_absolute():
            path = repo_root / source_file
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        seen_types: set[str] = set()  # one synthetic PBN per (file, type)
        for i, text in enumerate(lines, 1):
            for pbn_type, patterns in compiled.items():
                if pbn_type in seen_types:
                    continue
                if any(p.search(text) for p in patterns):
                    anchor_id = _anchor(source_file, i)
                    synthetic_id = f"{source_file}::synthetic_pbn::{pbn_type}::{i}"
                    graph.add_node(
                        synthetic_id,
                        label=f"{pbn_type}_client()",
                        file_type="code",
                        source_file=source_file,
                        source_location=f"L{i}",
                        _synthetic=True,
                        _pbn_type=pbn_type,
                    )
                    graph.add_edge(anchor_id, synthetic_id, relation="calls")
                    seen_types.add(pbn_type)

    return graph
