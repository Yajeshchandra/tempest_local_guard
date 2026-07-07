"""SP2 checks: on a realistic flat-layout repo (no prod/ folder), Rule (b) must
catch BOTH non-prod leak sources — a test fixture (tests/) AND a seed script
(scripts/, tagged DEV) — while NOT flagging the app's own data layer (app/,
generic NON_PROD), which is legitimate production code reaching its own DB.

This is the recall+precision balance that makes the tool usable on real repos:
before SP1/SP2 this fixture yielded 0 PBNs and 0 findings.
"""
from __future__ import annotations

from tempest.lde.orchestrator import run_detection


def _detect(repo_root):
    report = run_detection(str(repo_root)).to_dict()
    sources = {
        (f.get("source_node") or {}).get("source_file", "").replace("\\", "/")
        for f in report["findings"]
        if f["rule"] == "b"
    }
    return report, sources


def test_flatapp_discovers_the_db_boundary(flatapp_synced):
    repo_root, _ = flatapp_synced
    report, _ = _detect(repo_root)
    # SP1: the create_engine + connection string in app/db.py is discovered as a
    # PBN even though it sits in no prod/ folder.
    assert report["summary"]["pbn_count"] >= 1


def test_flatapp_catches_test_fixture_leak(flatapp_synced):
    repo_root, _ = flatapp_synced
    _, sources = _detect(repo_root)
    assert any("tests/db_fixtures.py" in s for s in sources), sources


def test_flatapp_catches_seed_script_leak(flatapp_synced):
    # SP2: scripts/ is DEV-tagged and Rule (b) now treats DEV (not only TEST) as
    # a leak source, so the seed script's reach into the prod DB is caught.
    repo_root, _ = flatapp_synced
    _, sources = _detect(repo_root)
    assert any("scripts/seed.py" in s for s in sources), sources


def test_flatapp_does_not_flag_own_data_layer(flatapp_synced):
    # Precision: app/services.py is the app's legitimate data layer (generic
    # NON_PROD, no explicit test/dev marker) — flagging it would be a false
    # positive, so it must stay out of the findings.
    repo_root, _ = flatapp_synced
    _, sources = _detect(repo_root)
    assert not any("services.py" in s for s in sources), sources
