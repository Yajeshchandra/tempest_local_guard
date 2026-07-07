"""SP3 checks: non-prod detection is generalized beyond folders. A leak in a
folder with NO test/dev/scripts marker (lib/) is still caught when the file
carries a non-prod signal — here a framework import (faker). Findings carry a
confidence so the strongest signals rank first.

This is what makes the tool work on ANY repo layout, not just ones that
happen to name their folders tests/ or scripts/.
"""
from __future__ import annotations

from pathlib import Path

from tempest.config import load_default_config
from tempest.lde.orchestrator import run_detection
from tempest.rie.boundary import classify_node


def _classify(label, source_file):
    config = load_default_config()
    node_data = {"label": label, "source_file": source_file, "source_location": "L1"}
    return classify_node("n1", node_data, config, Path("/nonexistent/repo"), {})


def test_filename_marker_generalizes_beyond_folders():
    # test_*.py in a non-test folder is still TEST.
    assert _classify("helper()", "app/test_helpers.py").env_tag == "TEST"
    # seed*.py anywhere is DEV.
    assert _classify("run()", "app/seed_users.py").env_tag == "DEV"


def _rule_b(report):
    return {
        (f.get("source_node") or {}).get("source_file", "").replace("\\", "/"): f
        for f in report["findings"]
        if f["rule"] == "b"
    }


def test_import_signal_catches_leak_in_unmarked_folder(flatapp_synced):
    # lib/user_ops.py is in NO non-prod folder and has NO test_* name —
    # only its `import faker` reveals it as non-prod. Folder-only detection
    # would miss this leak; the import signal catches it.
    repo_root, _ = flatapp_synced
    report = run_detection(str(repo_root)).to_dict()
    by_file = _rule_b(report)
    assert any("lib/user_ops.py" in f for f in by_file), list(by_file)
    # …and it's HIGH confidence (framework import is the strongest signal).
    hit = next(f for k, f in by_file.items() if "lib/user_ops.py" in k)
    assert hit["confidence"] == "high", hit


def test_folder_detected_leaks_are_medium_confidence(flatapp_synced):
    repo_root, _ = flatapp_synced
    report = run_detection(str(repo_root)).to_dict()
    by_file = _rule_b(report)
    seed = next((f for k, f in by_file.items() if "scripts/seed.py" in k), None)
    assert seed is not None and seed["confidence"] == "medium", seed


def test_app_data_layer_still_not_flagged(flatapp_synced):
    # Zero non-prod signal → treated as production app code → not a leak.
    repo_root, _ = flatapp_synced
    report = run_detection(str(repo_root)).to_dict()
    by_file = _rule_b(report)
    assert not any("services.py" in f for f in by_file), list(by_file)


def test_findings_sorted_high_confidence_first(flatapp_synced):
    repo_root, _ = flatapp_synced
    report = run_detection(str(repo_root)).to_dict()
    order = {"high": 0, "medium": 1, "low": 2}
    confs = [order[f["confidence"]] for f in report["findings"]]
    assert confs == sorted(confs), confs
