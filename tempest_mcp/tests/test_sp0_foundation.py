"""SP0 foundation checks: the incremental-sync fast path, cache clearing, and
the env-tag health signal in the report.

The incremental-sync fast path was silently dead before SP0 — it referenced an
undefined `logger`, raised NameError inside a bare `except Exception: pass`, and
fell through to a full graphify run every time. These tests lock the fix.
"""
from __future__ import annotations

import json

import pytest

from tempest.rie import sync as sync_mod
from tempest.rie.branch_state import BranchState


def test_incremental_sync_skips_graphify_when_commit_unchanged(tmp_path, monkeypatch):
    repo = tmp_path
    tempest_dir = repo / ".tempest" / "graphify-out"
    tempest_dir.mkdir(parents=True)
    (tempest_dir / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "n"}], "links": []}), encoding="utf-8"
    )

    # A prior sync recorded this exact commit.
    prior = {
        "repo_root": str(repo),
        "graph_json_path": str(tempest_dir / "graph.json"),
        "node_count": 1,
        "edge_count": 0,
        "branch": "main",
        "commit_sha": "deadbeef",
        "is_default_branch": True,
        "branch_warning": None,
        "duration_seconds": 0.0,
        "synced_at": "2026-01-01T00:00:00Z",
    }
    (repo / ".tempest" / "last_sync.json").write_text(json.dumps(prior), encoding="utf-8")

    monkeypatch.setattr(
        sync_mod, "get_branch_state",
        lambda _root: BranchState("main", "deadbeef", True, None),
    )

    def _boom(*_a, **_k):
        raise AssertionError("graphify must NOT run when the commit is unchanged")

    monkeypatch.setattr(sync_mod, "run_graphify_extract", _boom)

    result = sync_mod.sync_repo(str(repo))
    assert result.commit_sha == "deadbeef"
    assert result.node_count == 1


def test_full_sync_runs_graphify_when_commit_changed(tmp_path, monkeypatch):
    repo = tmp_path
    (repo / ".tempest" / "graphify-out").mkdir(parents=True)
    graph = repo / ".tempest" / "graphify-out" / "graph.json"
    graph.write_text(json.dumps({"nodes": [], "links": []}), encoding="utf-8")
    (repo / ".tempest" / "last_sync.json").write_text(
        json.dumps({"commit_sha": "oldsha"}), encoding="utf-8"
    )

    monkeypatch.setattr(
        sync_mod, "get_branch_state",
        lambda _root: BranchState("main", "newsha", True, None),
    )
    called = {"n": 0}

    def _extract(*_a, **_k):
        called["n"] += 1
        return graph

    monkeypatch.setattr(sync_mod, "run_graphify_extract", _extract)
    sync_mod.sync_repo(str(repo))
    assert called["n"] == 1


def test_report_exposes_env_histogram(leaky_repo_synced):
    from tempest.lde.orchestrator import run_detection

    repo_root, _ = leaky_repo_synced
    report = run_detection(str(repo_root)).to_dict()
    hist = report["summary"]["env_histogram"]
    assert isinstance(hist, dict) and hist, "env histogram should be populated"
    # the leaky fixture has both prod and non-prod nodes
    assert "PROD" in hist
