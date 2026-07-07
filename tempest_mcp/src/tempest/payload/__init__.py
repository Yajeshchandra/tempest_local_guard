"""Vendored content-based leak detector (the "Payload Engine").

Ported verbatim from the standalone `leak_detector_agent` project — pure
stdlib, no network, no ML. Detects hardcoded secrets, PII, high-entropy
strings, and format-specific leaks (.env / .ipynb / VCR / IDE / binary).

Exposed to tempest as a *standalone* content scan (see `tempest.payload.scan`)
that runs independently of the code graph. Tempest's graph/dataflow pipeline
does not use this package.
"""

from tempest.payload.engine import PayloadEngine

__all__ = ["PayloadEngine"]
