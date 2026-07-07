"""SP1 checks: resource boundaries must be discovered by *behavior* (the
client they instantiate / the connection string they hold), not only by living
in a prod/ folder. This is what lifts PBN yield on real repos, where the DB
client sits in no prod/ folder.

Regression guard: local/test doubles (DEV/TEST env) must NOT become PBNs, or
every LocalDatabase stub would light up.
"""
from __future__ import annotations

from pathlib import Path

from tempest.config import load_default_config
from tempest.rie.boundary import classify_node, load_overrides


def _classify(label, source_file, scanner_findings=None):
    config = load_default_config()
    node_data = {"label": label, "source_file": source_file, "source_location": "L1"}
    if scanner_findings:
        node_data["scanner_findings"] = scanner_findings
    # repo_root that won't match any file on disk → no folder/content signal,
    # so env stays NON_PROD (the real-repo default). Empty overrides.
    return classify_node("n1", node_data, config, Path("/nonexistent/repo"), {})


def test_resource_client_is_pbn_without_prod_folder():
    # A SQLAlchemy engine in a file with no prod/ marker → still a DB boundary.
    c = _classify("create_engine()", "app/db.py")
    assert c.is_pbn, f"expected PBN; reasons={c.reasons}"
    assert c.pbn_type == "database"
    assert not c.is_prod  # boundary-hood no longer requires PROD tag


def test_boto3_client_is_storage_boundary():
    c = _classify("boto3.client()", "app/uploads.py")
    assert c.is_pbn
    assert c.pbn_type == "storage"


def test_connection_string_makes_boundary_env_agnostic():
    c = _classify("connect()", "app/data.py", scanner_findings={"database_url": True})
    assert c.is_pbn
    assert c.pbn_type == "database"


def test_local_double_in_dev_folder_is_not_pbn():
    # Even though "create_engine" matches, a DEV-env node is a local double.
    c = _classify("create_engine()", "dev/local_db.py")
    assert c.env_tag == "DEV"
    assert not c.is_pbn, "local/test doubles must not be production boundaries"


def test_test_double_is_not_pbn():
    c = _classify("MongoClient()", "tests/conftest.py")
    assert c.env_tag == "TEST"
    assert not c.is_pbn


def test_plain_function_is_not_a_boundary():
    c = _classify("calculate_total()", "app/billing.py")
    assert not c.is_pbn
