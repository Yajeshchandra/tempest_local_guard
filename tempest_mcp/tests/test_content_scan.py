"""Standalone content-scan tool tests.

Plants secrets/PII across several file types in a temp repo and asserts the
whole-tree walk + format-specific handlers all fire, findings are redacted and
env-tagged, and the separate JSON report is written.
"""

from __future__ import annotations

import json
from pathlib import Path

from tempest.payload.scan import REPORT_NAME, run_content_scan

# 16-char AWS access-key example; 24+ char Stripe live key.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"

NOTEBOOK = json.dumps({
    "cells": [{
        "cell_type": "code",
        "source": ["print('customer record')\n"],
        "outputs": [{"output_type": "stream", "text": ["User SSN: 123-45-6789\n"]}],
    }],
    "metadata": {},
    "nbformat": 4,
    "nbformat_minor": 5,
})


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        f'AWS_ACCESS_KEY = "{AWS_KEY}"\nstripe_key = "{STRIPE_KEY}"\n',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("SECRET_TOKEN=supersecretvalue123\n", encoding="utf-8")
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "data.ipynb").write_text(NOTEBOOK, encoding="utf-8")
    # Should be pruned, must not appear in findings:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "leak.py").write_text(f'key = "{AWS_KEY}"\n', encoding="utf-8")
    return tmp_path


def test_content_scan_detects_across_file_types(tmp_path):
    repo = _make_repo(tmp_path)
    report = run_content_scan(repo)

    findings = report["findings"]
    types = {f["type"] for f in findings}

    # Whole-tree walk + format handlers all fired.
    assert "P-01" in types            # AWS key + Stripe key in app.py
    assert "P-02" in types            # secret in .env
    assert "P-05" in types            # PII inside the notebook cell output

    # Every finding is redacted and env-tagged.
    for f in findings:
        assert f["match_redacted"]
        assert not f["match_redacted"].endswith(AWS_KEY)  # never leak the raw secret
        assert "env" in f and f["env"]

    # Pruned directories are never scanned.
    assert all("node_modules" not in f["file"] for f in findings)

    # Fixture path is env-tagged TEST (folder marker), root files NON_PROD.
    notebook_findings = [f for f in findings if f["file"].endswith("data.ipynb")]
    assert notebook_findings and all(f["env"] == "TEST" for f in notebook_findings)

    # Separate report artifact written under .tempest/.
    report_path = repo / ".tempest" / REPORT_NAME
    assert report_path.exists()
    on_disk = json.loads(report_path.read_text(encoding="utf-8"))
    assert on_disk["summary"]["total"] == len(findings)
    assert on_disk["summary"]["by_type"]  # populated counter
