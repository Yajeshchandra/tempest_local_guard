"""Structured leak report — the JSON payload returned by tempest_detect and
persisted by storage/db.py for later retrieval via tempest_get_report."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from tempest.lde.evidence import Finding


@dataclass
class Report:
    repo_root: str
    findings: list[Finding]
    node_count: int
    edge_count: int
    prod_node_count: int
    pbn_count: int
    duration_seconds: float
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    scanned_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        by_rule = {"a": 0, "b": 0, "c": 0}
        for f in self.findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1

        return {
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at,
            "repo_root": self.repo_root,
            "summary": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "prod_node_count": self.prod_node_count,
                "pbn_count": self.pbn_count,
                "finding_count": len(self.findings),
                "findings_by_rule": by_rule,
                "duration_seconds": self.duration_seconds,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
