"""Step 5/7/10 verification: each policy rule fires on its exact planted
node and not on clean siblings; negative control on leak-free code finds
zero findings; re-run idempotency."""
from __future__ import annotations

from tempest.config import load_config
from tempest.lde.orchestrator import run_detection
from tempest.lde.policy import evaluate_rule_a, evaluate_rule_b, evaluate_rule_c
from tempest.rie.boundary import classify_graph
from tempest.rie.graph_loader import load_graph


def _prepare(repo_root, result):
    graph = load_graph(result.graph_json_path)
    config = load_config(repo_root)
    classifications = classify_graph(graph, config, repo_root)
    from tempest.rim import RepositoryIntelligenceModel
    return RepositoryIntelligenceModel(graph, classifications, config, str(repo_root))


# ---------------------------------------------------------------------------
# Rule (b) — test/seed code writing to a prod resource.
# ---------------------------------------------------------------------------
def test_rule_b_fires_on_planted_leak(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_b(rim)

    assert len(findings) == 1
    f = findings[0]
    assert f.source_node["label"] == "seed_fake_users()"
    assert "seed_script.py" in f.source_node["source_file"]
    assert f.target_node["label"] == "ProdDatabase"
    assert f.evidence["pbn_type"] == "database"
    assert len(f.paths) >= 1


def test_rule_b_does_not_fire_on_clean_sibling(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_b(rim)

    flagged_files = {f.source_node["source_file"] for f in findings}
    assert not any("clean_seed_script.py" in f for f in flagged_files)


# ---------------------------------------------------------------------------
# Rule (c) — prod data reaching non-prod logging/debug sinks.
# ---------------------------------------------------------------------------
def test_rule_c_fires_on_planted_leak(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_c(rim)

    assert len(findings) == 1
    f = findings[0]
    assert f.source_node["label"] == "dump_debug_log()"
    assert "debug_utils.py" in f.source_node["source_file"]
    assert f.target_node["label"] in ("ProdDatabase", "ProdUserService")


def test_rule_c_does_not_fire_on_clean_sibling(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_c(rim)

    flagged_files = {f.source_node["source_file"] for f in findings}
    assert not any("clean_debug_utils.py" in f for f in flagged_files)


# ---------------------------------------------------------------------------
# Rule (a) — hardcoded prod secrets in non-prod code.
# ---------------------------------------------------------------------------
def test_rule_a_fires_on_planted_leak(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_a(rim)

    assert len(findings) >= 1
    flagged_files = {f.source_node["source_file"] for f in findings}
    assert any("test_config.py" in f and "clean_" not in f for f in flagged_files)

    matched_literals = {f.evidence["matched_literal"] for f in findings}
    assert any("prod-db.internal.example.com" in lit for lit in matched_literals)


def test_rule_a_does_not_fire_on_clean_sibling(leaky_repo_synced):
    repo_root, result = leaky_repo_synced
    rim = _prepare(repo_root, result)
    findings = evaluate_rule_a(rim)

    flagged_files = {f.source_node["source_file"] for f in findings}
    assert not any("clean_test_config.py" in f for f in flagged_files)


# ---------------------------------------------------------------------------
# Full pipeline: exactly 3 findings, one per rule, on the leaky fixture.
# ---------------------------------------------------------------------------
def test_full_detection_finds_exactly_one_leak_per_rule(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced
    report = run_detection(repo_root)
    by_rule = report.to_dict()["summary"]["findings_by_rule"]
    assert by_rule == {"a": 1, "b": 1, "c": 1}


# ---------------------------------------------------------------------------
# Negative control: leak-free repo produces zero findings.
# ---------------------------------------------------------------------------
def test_negative_control_clean_repo_has_zero_findings(clean_repo_synced):
    repo_root, _ = clean_repo_synced
    report = run_detection(repo_root)
    d = report.to_dict()
    assert d["summary"]["finding_count"] == 0, d["findings"]


# ---------------------------------------------------------------------------
# Re-run idempotency: two consecutive scans produce identical findings.
# ---------------------------------------------------------------------------
def test_rerun_idempotency(leaky_repo_synced):
    repo_root, _ = leaky_repo_synced

    report1 = run_detection(repo_root).to_dict()
    report2 = run_detection(repo_root).to_dict()

    def _normalize(findings):
        return sorted(
            (f["rule"], f["source_node"]["id"], (f["target_node"] or {}).get("id"))
            for f in findings
        )

    assert _normalize(report1["findings"]) == _normalize(report2["findings"])
    assert report1["summary"]["findings_by_rule"] == report2["summary"]["findings_by_rule"]
