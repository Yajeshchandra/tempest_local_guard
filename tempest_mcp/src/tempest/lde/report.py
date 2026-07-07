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
    env_histogram: dict = field(default_factory=dict)
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
                "env_histogram": self.env_histogram,
                "finding_count": len(self.findings),
                "findings_by_rule": by_rule,
                "duration_seconds": self.duration_seconds,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Tempest Security Report: {self.repo_root}",
            "",
            "## Summary",
            "",
            f"- **Scan ID:** {self.scan_id}",
            f"- **Date:** {self.scanned_at}",
            f"- **Total findings:** {len(self.findings)}",
            f"- **Duration:** {self.duration_seconds:.2f}s",
            f"- **Graph size:** {self.node_count} nodes, {self.edge_count} edges",
            f"- **Production nodes:** {self.prod_node_count}",
            f"- **Production boundaries (PBNs):** {self.pbn_count}",
            "",
            "## Findings",
            "",
        ]

        if not self.findings:
            lines.append("No findings.")
            return "\n".join(lines) + "\n"

        # Sort findings: high severity first, then by rule
        sorted_findings = sorted(
            self.findings, 
            key=lambda f: (0 if f.severity == "critical" else 1 if f.severity == "high" else 2, f.rule, f.rule_name)
        )

        for index, finding in enumerate(sorted_findings, start=1):
            source_file = finding.source_node.get("source_file") or "unknown"
            source_loc = finding.source_node.get("source_location") or ""
            location = f"{source_file}:{source_loc}" if source_loc else source_file
            
            lines.extend([
                f"### {index}. {finding.rule_name} (Rule {finding.rule.upper()})",
                "",
                f"- **Severity:** {finding.severity.upper()}",
                f"- **Location:** `{location}`",
                f"- **Source Node:** {finding.source_node.get('label') or 'unknown'}",
            ])
            
            if finding.target_node:
                lines.append(f"- **Target Node:** {finding.target_node.get('label') or 'unknown'} ({finding.target_node.get('source_file') or ''})")
                
            if finding.paths:
                lines.append(f"- **Paths found:** {len(finding.paths)}")
                
            lines.extend([
                "",
                "**Suggested Fix:**",
                finding.suggested_fix,
                "",
            ])

        return "\n".join(lines) + "\n"
