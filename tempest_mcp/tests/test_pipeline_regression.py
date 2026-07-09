"""Pipeline regression tests — Phase 4.

Verifies the candidate/evidence pipeline introduced in the v3 redesign:
  • False-positive suppression for naked hashes, low-entropy assignments,
    placeholder values, and context-free base64 blobs.
  • Multi-syntax assignment detection (YAML, JSON, Python, env).
  • PII candidates bypass entropy gate but still receive context enrichment.
  • Severity and confidence are independent (confidence_locked=True).
"""

from __future__ import annotations

from pathlib import Path

from tempest.payload.engine import PayloadEngine

# Shared constants with test_content_scan.py
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# ── False positive suppression ────────────────────────────────────────────────


def test_assignment_high_entropy_produces_finding(tmp_path):
    """password = 'xK9mP2qRtL7wJnVbYhCdZfGi' — key context + high entropy → MEDIUM+ finding."""
    f = tmp_path / "config.py"
    f.write_text('password = "xK9mP2qRtL7wJnVbYhCdZfGi"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) >= 1, "Expected a finding for high-entropy password assignment"
    severities = {fi["severity"] for fi in findings}
    assert severities & {"HIGH", "MEDIUM"}, (
        f"Expected MEDIUM or HIGH severity, got: {severities}"
    )


def test_assignment_low_entropy_suppressed(tmp_path):
    """
    password = 'abcdefgh' — assignment candidate but entropy too low →
    required_signals gate drops the assignment candidate.
    """
    f = tmp_path / "config.py"
    f.write_text('password = "abcdefgh"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assignment_findings = [
        fi for fi in findings
        if any(e.startswith("assignment:") for e in fi.get("evidence", []))
    ]
    assert len(assignment_findings) == 0, (
        f"Low-entropy assignment should be suppressed: {assignment_findings}"
    )


def test_placeholder_password_suppressed(tmp_path):
    """password = 'changeme1' — low entropy placeholder → suppressed."""
    f = tmp_path / "app.py"
    f.write_text('password = "changeme1"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assignment_findings = [
        fi for fi in findings
        if any(e.startswith("assignment:") for e in fi.get("evidence", []))
    ]
    assert len(assignment_findings) == 0, (
        f"Placeholder password should be suppressed: {assignment_findings}"
    )


def test_naked_hash_produces_no_finding(tmp_path):
    """A bare high-entropy hash with no key=value structure → zero findings."""
    f = tmp_path / "checksums.txt"
    f.write_text("sha512-xK9mP2qRtL7wJnVbYhCdZfGiAbCdEfGh\n", encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) == 0, (
        f"Naked hash should produce no finding, got: {findings}"
    )


def test_integrity_hash_produces_no_finding(tmp_path):
    """
    \"integrity\": \"sha512-...\" — key 'integrity' is not a secret keyword
    → no candidate → no finding.
    """
    f = tmp_path / "package-lock.json"
    f.write_text(
        '{"integrity": "sha512-xK9mP2qRtL7wJnVbYhCdZfGiAbCdEfGhIjKlMnOpQrStUv=="}\n',
        encoding="utf-8",
    )

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) == 0, (
        f"Integrity hash should produce no finding, got: {findings}"
    )


def test_kubernetes_base64_no_context_no_finding(tmp_path):
    """data: dXNlcjpwYXNzd29yZA== — 'data' not a secret keyword → zero findings."""
    f = tmp_path / "secret.yaml"
    f.write_text("data: dXNlcjpwYXNzd29yZA==\n", encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) == 0, (
        f"base64 data without secret key should produce no finding, got: {findings}"
    )


def test_camelcase_identifier_no_finding(tmp_path):
    """PatchJson6902Transformer — no assignment structure → zero findings."""
    f = tmp_path / "config.go"
    f.write_text("var t PatchJson6902Transformer\n", encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) == 0, (
        f"CamelCase identifier should produce no finding, got: {findings}"
    )


# ── Multi-syntax assignment detection ────────────────────────────────────────


def test_yaml_assignment_detected(tmp_path):
    """api_secret: xK9mP2qRtL7wJnVbYhCdZfGi (YAML colon syntax) → finding."""
    f = tmp_path / "values.yaml"
    f.write_text("api_secret: xK9mP2qRtL7wJnVbYhCdZfGi\n", encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) >= 1, (
        "YAML assignment with secret key + high entropy should produce a finding"
    )


def test_json_assignment_detected(tmp_path):
    """\"token\": \"xK9mP2qRtL7wJnVbYhCdZfGi\" (JSON quoted-key syntax) → finding."""
    f = tmp_path / "config.json"
    f.write_text('{"token": "xK9mP2qRtL7wJnVbYhCdZfGi"}\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) >= 1, (
        "JSON assignment with secret key + high entropy should produce a finding"
    )


def test_toml_assignment_detected(tmp_path):
    """secret_key = \"xK9mP2qRtL7wJnVbYhCdZfGi\" (TOML/Python equals syntax) → finding."""
    f = tmp_path / "pyproject.toml"
    f.write_text('secret_key = "xK9mP2qRtL7wJnVbYhCdZfGi"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) >= 1, (
        "TOML/Python assignment with secret key + high entropy should produce a finding"
    )


# ── Path-based entropy gating ─────────────────────────────────────────────────


def test_skip_entropy_suppresses_assignment_in_docs(tmp_path):
    """
    password = 'xK9mP2qRtL7wJnVbYhCdZfGi' inside docs/ — should_skip_entropy()
    gates entropy enrichment → assignment candidate lacks entropy signal → dropped.
    """
    docs = tmp_path / "docs"
    docs.mkdir()
    f = docs / "guide.md"
    f.write_text('password = "xK9mP2qRtL7wJnVbYhCdZfGi"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assignment_findings = [
        fi for fi in findings
        if any(e.startswith("assignment:") for e in fi.get("evidence", []))
    ]
    assert len(assignment_findings) == 0, (
        f"Assignment in docs/ should be suppressed by should_skip_entropy: "
        f"{assignment_findings}"
    )


def test_regex_fires_even_in_docs(tmp_path):
    """
    AWS key in docs/ — regex candidate (confidence_locked=True) fires regardless
    of the entropy skip heuristic.
    """
    docs = tmp_path / "docs"
    docs.mkdir()
    f = docs / "example.py"
    f.write_text(f'key = "{AWS_KEY}"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    regex_findings = [
        fi for fi in findings
        if any(e.startswith("regex:") for e in fi.get("evidence", []))
    ]
    assert len(regex_findings) >= 1, (
        "Regex candidate should fire even inside docs/"
    )


# ── PII pipeline behavior ─────────────────────────────────────────────────────


def test_pii_low_entropy_still_detected(tmp_path):
    """SSN 123-45-6789 has very low entropy but is PII — entropy gate is bypassed."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    f = fixtures / "users.json"
    f.write_text('{"ssn": "123-45-6789"}\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    pii_findings = [fi for fi in findings if fi.get("type") == "P-04"]
    assert len(pii_findings) >= 1, (
        "SSN in fixture file should be detected regardless of entropy"
    )


def test_pii_has_evidence_field(tmp_path):
    """PII candidates skip entropy but still produce a non-empty evidence list."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    f = fixtures / "records.json"
    f.write_text('{"ssn": "123-45-6789"}\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    pii_findings = [fi for fi in findings if fi.get("type") == "P-04"]
    for fi in pii_findings:
        assert isinstance(fi.get("evidence"), list), (
            f"PII finding should have evidence list: {fi}"
        )
        assert len(fi["evidence"]) >= 1, (
            f"PII finding evidence should have at least the pii: signal: {fi['evidence']}"
        )


def test_email_pii_detected_in_fixture(tmp_path):
    """Email address in fixture file → P-04 regardless of entropy."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    f = fixtures / "seed.json"
    f.write_text('{"email": "john.doe@example.com"}\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    pii_findings = [fi for fi in findings if fi.get("type") == "P-04"]
    assert len(pii_findings) >= 1, (
        "Email in fixture file should be detected as P-04 PII"
    )


# ── Severity/confidence independence ──────────────────────────────────────────


def test_severity_and_confidence_are_independent(tmp_path):
    """
    AWS key in docs/ → severity=HIGH (locked), confidence<1.0 (path penalty).
    Verifies confidence_locked=True pins severity independently of confidence.
    """
    docs = tmp_path / "docs"
    docs.mkdir()
    f = docs / "example.py"
    f.write_text(f'AWS_ACCESS_KEY = "{AWS_KEY}"\n', encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    aws_findings = [fi for fi in findings if "AWS" in fi.get("description", "")]
    assert len(aws_findings) >= 1, "AWS key should be detected even in docs/"

    for fi in aws_findings:
        assert fi["severity"] == "HIGH", (
            f"Regex severity must be HIGH regardless of path, got: {fi['severity']}"
        )
        assert fi["confidence"] < 1.0, (
            f"Confidence should be < 1.0 in low-value path, got: {fi['confidence']}"
        )


def test_env_file_regex_wins_over_assignment(tmp_path):
    """
    SECRET_TOKEN=supersecretvalue123 in .env — P-02 regex fires first;
    deduplication keeps the regex candidate, not the assignment one.
    """
    f = tmp_path / ".env"
    f.write_text("SECRET_TOKEN=supersecretvalue123\n", encoding="utf-8")

    findings = PayloadEngine().scan([str(f)])

    assert len(findings) >= 1, ".env secret should be detected"
    regex_findings = [
        fi for fi in findings
        if any(e.startswith("regex:") for e in fi.get("evidence", []))
    ]
    assert len(regex_findings) >= 1, (
        "Regex provider should win over assignment provider for .env secrets"
    )
