from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from tempest.rie.boundary import NodeClassification


@dataclass
class RepositoryIntelligenceModel:
    """The formal contract between the Repository Intelligence Engine (RIE)
    and the Leak Detection Engine (LDE).
    
    Contains the full graph, environment map, and production boundary index.
    The LDE consumes this object exclusively, decoupling detection logic from
    the mechanics of AST extraction, classification, and file-system I/O.
    """
    graph: nx.DiGraph
    classifications: dict[str, NodeClassification]
    config: dict[str, Any]
    repo_root: str
