"""Focused regression tests for the 4 dataset-run fixes:
  1. P-04 CSV/TSV fixtures scanned by the content engine.
  2. Rule (b) content fallback requires positive prod evidence.
  3. Rule (b) structural skips connection-lifecycle PBN targets.
  4. AST augmentation creates synthetic PBNs for third-party clients, scoped
     to DEV/TEST files, promoted to PBN/prod only with a co-located prod id.
"""
from __future__ import annotations

import networkx as nx

from tempest.config import load_default_config
from tempest.lde.policy import evaluate_rule_b, evaluate_rule_b_content
from tempest.payload.engine import PayloadEngine, SUPPORTED_EXTENSIONS
from tempest.rie.augment import augment_graph_with_ast
from tempest.rie.boundary import classify_node, load_overrides
from tempest.rim import RepositoryIntelligenceModel


def _rim(graph, config, repo_root):
    from tempest.rie.boundary import classify_graph
    classifications = classify_graph(graph, config, str(repo_root))
    return RepositoryIntelligenceModel(graph, classifications, config, str(repo_root))


# ---------------------------------------------------------------------------
# Fix 1 — P-04 CSV/TSV
# ---------------------------------------------------------------------------
def test_csv_tsv_are_supported_extensions():
    assert ".csv" in SUPPORTED_EXTENSIONS
    assert ".tsv" in SUPPORTED_EXTENSIONS


def test_csv_fixture_flags_pii(tmp_path):
    fixtures_dir = tmp_path / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True)
    csv_path = fixtures_dir / "customers.csv"
    csv_path.write_text(
        "id,email,ssn\n1,alice@example.com,501-22-8837\n", encoding="utf-8"
    )
    findings = PayloadEngine().scan([str(csv_path)])
    assert any(f["type"] == "P-04" for f in findings)


# ---------------------------------------------------------------------------
# Fix 2 — Rule (b) content fallback prod-gate
# ---------------------------------------------------------------------------
def _write_test_file(tmp_path, rel_path: str, content: str):
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _graph_with_single_test_function(tmp_path, rel_path: str, func_name: str):
    graph = nx.DiGraph()
    graph.add_node(
        f"mod_{func_name}",
        label=f"{func_name}()",
        file_type="code",
        source_file=rel_path,
        source_location="L1",
    )
    return graph


def test_rule_b_content_skips_plain_unit_test_with_no_config_evidence(tmp_path):
    _write_test_file(
        tmp_path,
        "tests/test_models.py",
        "def test_get_by_id():\n    user = User('a', 'a@b.com')\n    user.save()\n",
    )
    graph = _graph_with_single_test_function(tmp_path, "tests/test_models.py", "test_get_by_id")
    config = load_default_config()
    rim = _rim(graph, config, tmp_path)
    findings = evaluate_rule_b_content(rim)
    assert findings == []


def test_rule_b_content_fires_with_prod_config_marker(tmp_path):
    _write_test_file(
        tmp_path,
        "scripts/seed_users.py",
        "from conduit.settings import ProdConfig\n"
        "def seed():\n    app = create_app(ProdConfig)\n    user.save()\n",
    )
    graph = _graph_with_single_test_function(tmp_path, "scripts/seed_users.py", "seed")
    config = load_default_config()
    rim = _rim(graph, config, tmp_path)
    findings = evaluate_rule_b_content(rim)
    assert len(findings) == 1
    assert "seed_users.py" in findings[0].source_node["source_file"]


def test_rule_b_content_fires_with_prod_dsn_literal(tmp_path):
    _write_test_file(
        tmp_path,
        "scripts/debug_dump_users.py",
        'PROD_DSN = "postgresql://admin:pw@prod-db.internal.example.com:5432/main"\n'
        "def dump_users():\n    cur.execute('SELECT * FROM auth_user')\n",
    )
    graph = _graph_with_single_test_function(tmp_path, "scripts/debug_dump_users.py", "dump_users")
    config = load_default_config()
    rim = _rim(graph, config, tmp_path)
    findings = evaluate_rule_b_content(rim)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Fix 3 — Rule (b) structural lifecycle exclusion
# ---------------------------------------------------------------------------
def _rule_b_graph_with_pbn(pbn_label: str):
    graph = nx.DiGraph()
    graph.add_node(
        "test_fn",
        label="app()",
        file_type="code",
        source_file="tests/conftest.py",
        source_location="L1",
    )
    graph.add_node(
        "pbn_target",
        label=pbn_label,
        file_type="code",
        source_file="app/db.py",
        source_location="L1",
        scanner_findings={"database_url": True},
    )
    graph.add_edge("test_fn", "pbn_target", relation="calls")
    return graph


def test_rule_b_skips_lifecycle_target():
    graph = _rule_b_graph_with_pbn("close_db_connection()")
    config = load_default_config()
    rim = _rim(graph, config, "/tmp/repo")
    findings = evaluate_rule_b(rim)
    assert findings == []


def test_rule_b_fires_on_non_lifecycle_target():
    graph = _rule_b_graph_with_pbn("execute_query()")
    config = load_default_config()
    rim = _rim(graph, config, "/tmp/repo")
    findings = evaluate_rule_b(rim)
    assert len(findings) == 1
    assert findings[0].target_node["label"] == "execute_query()"


# ---------------------------------------------------------------------------
# Fix 4 — AST augmentation + scoped PBN promotion
# ---------------------------------------------------------------------------
def test_augment_creates_synthetic_pbn_for_boto3_client(tmp_path):
    _write_test_file(
        tmp_path,
        "scripts/upload_avatars_to_s3.py",
        "import boto3\n"
        "def upload_avatars():\n"
        "    s3 = boto3.client('s3')\n"
        "    s3.put_object(Bucket='prod-user-uploads')\n",
    )
    graph = nx.DiGraph()
    graph.add_node(
        "scripts_upload_avatars_to_s3_upload_avatars",
        label="upload_avatars()",
        file_type="code",
        source_file="scripts/upload_avatars_to_s3.py",
        source_location="L2",
    )
    config = load_default_config()
    augment_graph_with_ast(graph, tmp_path, config)
    synthetic = [n for n, d in graph.nodes(data=True) if d.get("_synthetic")]
    assert len(synthetic) == 1
    assert graph.nodes[synthetic[0]]["label"] == "boto3.client()"
    assert graph.has_edge("scripts_upload_avatars_to_s3_upload_avatars", synthetic[0])


def test_augment_skips_prod_classified_files(tmp_path):
    _write_test_file(
        tmp_path,
        "app/db/events.py",
        "import asyncpg\n"
        "async def connect_to_db():\n"
        "    pool = await asyncpg.create_pool()\n",
    )
    graph = nx.DiGraph()
    graph.add_node(
        "app_db_events_connect_to_db",
        label="connect_to_db()",
        file_type="code",
        source_file="app/db/events.py",
        source_location="L2",
    )
    config = load_default_config()
    augment_graph_with_ast(graph, tmp_path, config)
    synthetic = [n for n, d in graph.nodes(data=True) if d.get("_synthetic")]
    assert synthetic == []


def test_synthetic_node_promoted_to_pbn_with_companion_prod_identifier(tmp_path):
    _write_test_file(
        tmp_path,
        "scripts/backfill_emails.py",
        'PROD_DSN = "postgresql://admin:pw@prod-db.internal.example.com:5432/main"\n'
        "import asyncpg\n"
        "async def backfill():\n"
        "    conn = await asyncpg.connect(PROD_DSN)\n",
    )
    graph = nx.DiGraph()
    graph.add_node(
        "scripts_backfill_emails_backfill",
        label="backfill()",
        file_type="code",
        source_file="scripts/backfill_emails.py",
        source_location="L3",
    )
    config = load_default_config()
    augment_graph_with_ast(graph, tmp_path, config)
    synthetic_id = next(n for n, d in graph.nodes(data=True) if d.get("_synthetic"))
    c = classify_node(
        synthetic_id, graph.nodes[synthetic_id], config, tmp_path, load_overrides(tmp_path)
    )
    assert c.is_pbn
    assert c.is_prod
    assert c.pbn_type == "database"


def test_synthetic_node_not_promoted_without_companion_prod_identifier(tmp_path):
    _write_test_file(
        tmp_path,
        "tests/conftest.py",
        "from tests.fake_asyncpg_pool import FakeAsyncPGPool\n"
        "async def initialized_app():\n"
        "    pool = await FakeAsyncPGPool.create_pool(None)\n",
    )
    graph = nx.DiGraph()
    graph.add_node(
        "tests_conftest_initialized_app",
        label="initialized_app()",
        file_type="code",
        source_file="tests/conftest.py",
        source_location="L2",
    )
    config = load_default_config()
    augment_graph_with_ast(graph, tmp_path, config)
    synthetic_ids = [n for n, d in graph.nodes(data=True) if d.get("_synthetic")]
    assert len(synthetic_ids) == 1
    c = classify_node(
        synthetic_ids[0], graph.nodes[synthetic_ids[0]], config, tmp_path, load_overrides(tmp_path)
    )
    assert not c.is_pbn


# ---------------------------------------------------------------------------
# Phase 1 — content-scanner precision (false-positive suppression)
# ---------------------------------------------------------------------------
def _scan(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return PayloadEngine().scan([str(p)])


def test_dependency_lockfile_hashes_skipped(tmp_path):
    body = '{\n  "node_modules/x": {\n    "integrity": "sha512-' + "aB3xZ9" * 12 + '"\n  }\n}\n'
    assert _scan(tmp_path, "package-lock.json", body) == []


def test_generated_protobuf_file_skipped(tmp_path):
    body = "# Generated by the protocol buffer compiler.  DO NOT EDIT!\nX = b'" + "aZ9bK2" * 10 + "'\n"
    assert _scan(tmp_path, "svc_pb2.py", body) == []


def test_generated_header_marker_skipped(tmp_path):
    body = "// <auto-generated>\nvar x = \"" + "Qw3rTy9" * 8 + "\";\n"
    assert _scan(tmp_path, "Model.cs", body) == []


def test_dotted_identifier_not_flagged(tmp_path):
    findings = _scan(tmp_path, "a.py", "x = Npgsql.EntityFrameworkCore.PostgreSQL.Metadata\n")
    assert [f for f in findings if f["type"] == "P-01"] == []


def test_generic_type_param_not_flagged(tmp_path):
    findings = _scan(tmp_path, "a.cs", "Assert.ThrowsExactly<OrderingDomainException>(() => x);\n")
    assert [f for f in findings if f["type"] == "P-01"] == []


def test_import_line_not_flagged(tmp_path):
    findings = _scan(tmp_path, "a.java", "import static anthos.samples.bankofanthos.ledgerwriter.LedgerWriterController;\n")
    assert [f for f in findings if f["type"] == "P-01"] == []


def test_env_var_interpolation_not_flagged(tmp_path):
    findings = _scan(tmp_path, "a.sh", "TOKEN=${SUPER_SECRET_TOKEN_VALUE_1234}\n")
    assert [f for f in findings if f["type"] == "P-01"] == []


def test_llm_tool_call_id_not_flagged(tmp_path):
    findings = _scan(tmp_path, "cassettes/x_cassette.yaml", 'id: call_fNhLOKLBdmNBsZIXI3wpQ9M4\n')
    assert [f for f in findings if f["type"] == "P-01"] == []


def test_wrapper_jar_not_flagged(tmp_path):
    p = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x00\x01binary")
    assert PayloadEngine().scan([str(p)]) == []


def test_text_lockfile_is_low_not_high(tmp_path):
    p = tmp_path / "Cargo.lock"
    p.write_text("# lockfile\n", encoding="utf-8")
    findings = PayloadEngine().scan([str(p)])
    assert len(findings) == 1 and findings[0]["type"] == "P-06" and findings[0]["severity"] == "LOW"


def test_real_secret_still_flagged(tmp_path):
    # Regression guard: a genuine AWS key must survive all the new skips.
    findings = _scan(tmp_path, "config.py", 'AWS_KEY = "AKIAZ7Q9TESTNPROD4NP"\n')
    assert any(f["type"] == "P-01" for f in findings)
