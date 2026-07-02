from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tempest.rie.sync import sync_repo

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LEAKY_REPO = FIXTURES_DIR / "leaky_repo"
CLEAN_REPO = FIXTURES_DIR / "clean_repo"


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
