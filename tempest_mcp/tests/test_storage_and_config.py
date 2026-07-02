"""Step 8/9 verification: SQLite persistence + config loading/merging."""
from __future__ import annotations

from tempest.config import load_config, load_default_config
from tempest.lde.orchestrator import run_detection
from tempest.storage.db import get_report, list_scans, save_report


def test_default_config_loads():
    config = load_default_config()
    assert "boundary" in config
    assert "pbn_patterns" in config
    assert "database" in config["pbn_patterns"]


def test_load_config_merges_defaults_when_no_user_config(tmp_path):
    config = load_config(tmp_path)
    assert config["boundary"]["folder_markers"]["prod"] == ["prod", "production"]


def test_load_config_user_override_wins(tmp_path):
    tempest_dir = tmp_path / ".tempest"
    tempest_dir.mkdir()
    (tempest_dir / "tempest.config.yaml").write_text(
        "known_prod_identifiers:\n  - my-custom-prod-marker\n", encoding="utf-8"
    )
    config = load_config(tmp_path)
    assert config["known_prod_identifiers"] == ["my-custom-prod-marker"]
    # Defaults for untouched keys still present.
    assert "pbn_patterns" in config


def test_save_and_get_report_roundtrip(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced
    report = run_detection(repo_root)
    scan_id = save_report(repo_root, report)

    fetched = get_report(repo_root, scan_id)
    assert fetched is not None
    assert fetched["scan_id"] == scan_id
    assert fetched["summary"]["finding_count"] == len(report.findings)


def test_get_report_latest_when_no_scan_id(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced
    report = run_detection(repo_root)
    save_report(repo_root, report)

    latest = get_report(repo_root, scan_id=None)
    assert latest is not None
    assert latest["scan_id"] == report.scan_id


def test_list_scans_returns_history(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced
    report = run_detection(repo_root)
    save_report(repo_root, report)

    history = list_scans(repo_root)
    assert len(history) >= 1
    assert history[0]["scan_id"] == report.scan_id


def test_get_report_missing_scan_id_returns_none(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced
    assert get_report(repo_root, scan_id="does-not-exist") is None
