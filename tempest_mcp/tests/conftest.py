from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tempest.rie.sync import sync_repo

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LEAKY_REPO = FIXTURES_DIR / "leaky_repo"
CLEAN_REPO = FIXTURES_DIR / "clean_repo"
FLATAPP_REPO = FIXTURES_DIR / "flatapp"


def _fresh_sync(repo_root: Path):
    tempest_dir = repo_root / ".tempest"
    if tempest_dir.exists():
        shutil.rmtree(tempest_dir)
    return sync_repo(repo_root)


@pytest.fixture(scope="session")
def leaky_repo_synced():
    """Sync the planted-leak fixture repo once per test session."""
    result = _fresh_sync(LEAKY_REPO)
    yield LEAKY_REPO, result


@pytest.fixture(scope="session")
def clean_repo_synced():
    """Sync the leak-free fixture repo once per test session."""
    result = _fresh_sync(CLEAN_REPO)
    yield CLEAN_REPO, result


@pytest.fixture(scope="session")
def flatapp_synced():
    """Sync the realistic flat-layout fixture (no prod/ folder) once per session.

    This is the real-repo shape SP1/SP2 target: the DB client sits in app/db.py
    with a real create_engine + connection string, reached by a seed script
    (scripts/) and a test fixture (tests/) — the two planted leaks — while the
    app's own data layer (app/services.py) must NOT be flagged."""
    result = _fresh_sync(FLATAPP_REPO)
    yield FLATAPP_REPO, result
