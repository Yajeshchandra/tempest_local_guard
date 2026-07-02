"""The Finding data model shared by all 3 policy rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    rule: str  # "a" | "b" | "c"
    rule_name: str
    severity: str  # "high" | "medium" | "low"
    source_node: dict[str, Any]  # {id, label, source_file, source_location}
    target_node: dict[str, Any] | None  # PBN / sink node summary, or None for rule (a)
    paths: list[list[dict]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    suggested_fix: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "paths": self.paths,
            "evidence": self.evidence,
            "suggested_fix": self.suggested_fix,
        }


def summarize_node(graph, node_id: str) -> dict[str, Any]:
    data = graph.nodes.get(node_id, {})
    return {
        "id": node_id,
        "label": data.get("label"),
        "source_file": data.get("source_file"),
        "source_location": data.get("source_location"),
    }
