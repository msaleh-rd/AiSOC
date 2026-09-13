"""Optional Temporal.io durability overlay for the investigation pipeline.

Nothing in this package is imported by the default request path — the
in-process LangGraph pipeline (:mod:`app.graph.runner`) remains the default
orchestrator. This package is only touched when an operator opts in via the
``temporal`` Docker Compose profile + ``AISOC_AGENT_TEMPORAL_MODE=1`` (see
:mod:`app.temporal.adapter`), or runs the worker directly
(``python -m app.temporal.worker``).
"""

from __future__ import annotations
