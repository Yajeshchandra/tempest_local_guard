"""SQLite persistence for scan history + findings.

Schema lives in `<repo>/.tempest/tempest.db`. Kept intentionally simple: one
row per scan (with the full report JSON blob) plus a normalized findings
table for potential future querying. The JSON blob is the source of truth
for `tempest_get_report`; the findings table exists for cheap aggregate
queries (e.g. "how many rule-b findings over time") without deserializing
every report.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from tempest.paths import RepoPaths

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    repo_root TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    prod_node_count INTEGER NOT NULL,
    pbn_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    report_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    rule TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_node_id TEXT,
    target_node_id TEXT,
    finding_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo_root ON scans(repo_root);
"""


@contextmanager
def _connect(repo_root: str | Path):
    paths = RepoPaths(repo_root)
    paths.ensure_tempest_dir()
    conn = sqlite3.connect(str(paths.db_file))
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_report(repo_root: str | Path, report: Any) -> str:
    """Persist a Report (tempest.lde.report.Report) to SQLite. Returns the
    scan_id."""
    payload = report.to_dict()
    summary = payload["summary"]

    with _connect(repo_root) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (scan_id, repo_root, scanned_at, node_count, edge_count,
                 prod_node_count, pbn_count, finding_count, duration_seconds, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["scan_id"],
                payload["repo_root"],
                payload["scanned_at"],
                summary["node_count"],
                summary["edge_count"],
                summary["prod_node_count"],
                summary["pbn_count"],
                summary["finding_count"],
                summary["duration_seconds"],
                json.dumps(payload),
            ),
        )

        conn.execute("DELETE FROM findings WHERE scan_id = ?", (payload["scan_id"],))
        for finding in payload["findings"]:
            conn.execute(
                """
                INSERT INTO findings
                    (scan_id, rule, rule_name, severity, source_node_id, target_node_id, finding_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["scan_id"],
                    finding["rule"],
                    finding["rule_name"],
                    finding["severity"],
                    (finding.get("source_node") or {}).get("id"),
                    (finding.get("target_node") or {}).get("id"),
                    json.dumps(finding),
                ),
            )

    return payload["scan_id"]


def get_report(repo_root: str | Path, scan_id: str | None = None) -> dict | None:
    """Fetch a previously persisted report by scan_id, or the latest scan
    for the repo if scan_id is None. Returns None if no matching scan
    exists."""
    with _connect(repo_root) as conn:
        conn.row_factory = sqlite3.Row
        if scan_id:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT report_json FROM scans ORDER BY scanned_at DESC, id DESC LIMIT 1"
            ).fetchone()

        if row is None:
            return None
        return json.loads(row["report_json"])


def list_scans(repo_root: str | Path, limit: int = 20) -> list[dict]:
    """List scan history (most recent first), without the full findings
    payload — just summary metadata."""
    with _connect(repo_root) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT scan_id, repo_root, scanned_at, node_count, edge_count,
                   prod_node_count, pbn_count, finding_count, duration_seconds
            FROM scans
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
