"""Tempest MCP server entrypoint.

Exposes Tempest's leak-detection pipeline as MCP tools over stdio, so any
MCP-capable coding agent (Claude Code, Codex, Copilot, ...) can drive it.
Zero cloud calls, zero API keys, fully local.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from tempest.config import load_config, write_default_user_config_if_missing
from tempest.lde.orchestrator import DetectionError, run_detection
from tempest.rie.boundary import (
    classify_node,
    load_overrides,
    save_override,
)
from tempest.rie.graph_loader import GraphLoadError, load_graph
from tempest.rie.sync import GraphifyExtractError, GraphifyNotFoundError, sync_repo
from tempest.paths import RepoPaths
from tempest.storage.db import get_report, list_scans, save_report

logging.basicConfig(level=logging.INFO, stream=None)
logger = logging.getLogger("tempest")

mcp = FastMCP("tempest")


@mcp.tool()
def tempest_sync(repo_path: str) -> dict[str, Any]:
    """Build or refresh Tempest's understanding of a repository.

    Runs `graphify extract` on the given repo, loads the resulting code
    graph, and caches it under `<repo_path>/.tempest/`. Call this before
    `tempest_detect`. Safe to re-run at any time (e.g. after code changes)
    to refresh the cached graph.

    Args:
        repo_path: Absolute path to the root of the repository to scan.

    Returns:
        Summary of the sync: node/edge counts, current git branch, commit
        sha, and a warning if the working tree isn't on the repo's default
        branch (prod is assumed to track main/master).
    """
    try:
        write_default_user_config_if_missing(repo_path)
        result = sync_repo(repo_path)
    except GraphifyNotFoundError as exc:
        return {"error": "graphify_not_found", "message": str(exc)}
    except GraphifyExtractError as exc:
        return {"error": "graphify_extract_failed", "message": str(exc)}

    payload = result.to_dict()
    payload["ok"] = True
    if result.branch_warning:
        payload["warning"] = result.branch_warning
    return payload


@mcp.tool()
def tempest_detect(repo_path: str) -> dict[str, Any]:
    """Run Tempest's leak-detection pipeline against a previously synced repo.

    Requires `tempest_sync` to have been run first. Performs Production
    Boundary Node (PBN) selection, reverse reachability from every PBN, and
    evaluates all 3 policy rules:
      (a) hardcoded prod secrets in non-prod code
      (b) test/seed code writing to a prod resource
      (c) prod data reaching non-prod logging/debug sinks

    Args:
        repo_path: Absolute path to the root of the repository to scan
            (must match a repo previously passed to tempest_sync).

    Returns:
        A structured JSON leak report: summary counts plus a list of
        findings, each with rule, severity, source/target node, evidence
        path(s), and a suggested fix. Explain these findings to the
        developer in plain language.
    """
    try:
        report = run_detection(repo_path)
    except DetectionError as exc:
        return {"error": "detection_failed", "message": str(exc)}

    payload = report.to_dict()
    payload["ok"] = True

    try:
        save_report(repo_path, report)
    except Exception as exc:  # pragma: no cover - persistence must not block detection
        logger.warning("Failed to persist scan report: %s", exc)

    return payload


@mcp.tool()
def tempest_get_report(repo_path: str, scan_id: str | None = None) -> dict[str, Any]:
    """Cheap re-fetch of a previous tempest_detect scan, without re-running
    detection.

    Args:
        repo_path: Absolute path to the repo root (same value passed to
            tempest_sync/tempest_detect).
        scan_id: Specific scan to fetch. If omitted, returns the most recent
            scan for this repo.

    Returns:
        The same structured report shape as tempest_detect, plus a
        `scan_history` list (recent scan_ids/timestamps/finding counts) so
        the caller can pick a different scan_id if needed.
    """
    report = get_report(repo_path, scan_id)
    history = list_scans(repo_path)

    if report is None:
        return {
            "error": "no_report_found",
            "message": (
                f"No scan found for scan_id={scan_id!r}. Run tempest_detect first."
                if scan_id
                else "No scans found for this repo yet. Run tempest_sync then tempest_detect first."
            ),
            "scan_history": history,
        }

    report["ok"] = True
    report["scan_history"] = history
    return report


@mcp.tool()
def tempest_classify_boundary(
    repo_path: str,
    node_id: str,
    set_env_tag: str | None = None,
    set_is_pbn: bool | None = None,
    set_pbn_type: str | None = None,
) -> dict[str, Any]:
    """Inspect why a node was classified PROD/NON-PROD, or set a manual
    override.

    Call with only `node_id` to inspect the current classification and the
    reasons behind it. Pass `set_env_tag` / `set_is_pbn` / `set_pbn_type` to
    persist a manual override for this node — overrides always win over
    every heuristic on future scans.

    Args:
        repo_path: Absolute path to the repo root.
        node_id: The graph node id to inspect or override (as returned in a
            finding's source_node/target_node, or from the synced graph).
        set_env_tag: If provided, override the node's environment tag
            (e.g. "PROD", "NON_PROD", "TEST", "DEV", "STAGING", "QA").
        set_is_pbn: If provided, override whether this node is treated as a
            Production Boundary Node.
        set_pbn_type: If provided, override the PBN's boundary_type
            (database/storage/messaging/network).

    Returns:
        The node's current classification (after any override applied) and
        the reasons/heuristics that produced it.
    """
    paths = RepoPaths(repo_path)
    if not paths.graph_json.exists():
        return {"error": "no_synced_graph", "message": "Run tempest_sync first."}

    try:
        graph = load_graph(paths.graph_json)
    except GraphLoadError as exc:
        return {"error": "graph_load_failed", "message": str(exc)}

    if node_id not in graph:
        return {"error": "node_not_found", "message": f"No node with id {node_id!r} in the synced graph."}

    if set_env_tag is not None or set_is_pbn is not None or set_pbn_type is not None:
        save_override(
            repo_path,
            node_id,
            env_tag=set_env_tag,
            is_pbn=set_is_pbn,
            pbn_type=set_pbn_type,
        )

    config = load_config(repo_path)
    overrides = load_overrides(repo_path)
    node_data = dict(graph.nodes[node_id])
    classification = classify_node(node_id, node_data, config, paths.repo_root, overrides)

    result = classification.to_dict()
    result["ok"] = True
    result["node"] = {
        "id": node_id,
        "label": node_data.get("label"),
        "source_file": node_data.get("source_file"),
        "source_location": node_data.get("source_location"),
    }
    return result


def run() -> None:
    """Entrypoint for `python -m tempest.server` / the `tempest-server` script."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
