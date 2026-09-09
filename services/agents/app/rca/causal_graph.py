"""CausalGraphBuilder — builds a NetworkX DiGraph from investigation entities
and events for root cause analysis.

The graph captures causal relationships between entities (services, users, IPs,
processes) based on:
  * Temporal ordering of events
  * Entity co-occurrence in the same event
  * Explicit dependency relationships

This graph is consumed by ``PageRankRCA`` to identify the most likely root
cause entity.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

import structlog

try:
    import networkx as nx
except ImportError:  # pragma: no cover — optional dependency
    nx = None  # type: ignore[assignment]

from app.compression.models import CorrelatedEvent

logger = structlog.get_logger()


class CausalGraphBuilder:
    """Builds a causal ``networkx.DiGraph`` from investigation events.

    Nodes represent entities (services, IPs, users, hostnames).
    Edges represent causal relationships (temporal ordering + co-occurrence).
    """

    def __init__(self) -> None:
        if nx is None:
            raise ImportError(
                "networkx is required for causal graph analysis. "
                "Install it with: pip install networkx"
            )
        self._graph: nx.DiGraph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def build_from_events(
        self,
        events: list[CorrelatedEvent],
        *,
        known_dependencies: dict[str, list[str]] | None = None,
    ) -> nx.DiGraph:
        """Build the causal graph from a list of compressed events.

        Args:
            events: Compressed events from the compression pipeline.
            known_dependencies: Optional dict of ``entity → [dependencies]``
                (e.g. from a service mesh or CMDB).

        Returns:
            The built ``networkx.DiGraph``.
        """
        self._graph = nx.DiGraph()

        if not events:
            return self._graph

        # Sort by timestamp for temporal ordering.
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Add nodes.
        entity_events: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        for event in sorted_events:
            entity_events[event.entity_id].append(event)
            self._add_entity_node(event)

        # Add edges from known dependencies. Edges represent cause -> effect
        # (matching the temporal-inference edges below): if `entity` depends
        # on `dep`, then a failure/anomaly in `dep` is the upstream cause and
        # `entity` is the downstream effect, so the edge points dep -> entity.
        if known_dependencies:
            for entity, deps in known_dependencies.items():
                for dep in deps:
                    if entity in self._graph and dep in self._graph:
                        self._graph.add_edge(dep, entity, weight=1.0, relationship="dependency")

        # Infer causal edges from temporal ordering within sliding windows.
        self._infer_temporal_edges(sorted_events)

        # Infer co-occurrence edges (entities that appear in the same time window).
        self._infer_cooccurrence_edges(sorted_events)

        logger.info(
            "rca.causal_graph.built",
            nodes=self._graph.number_of_nodes(),
            edges=self._graph.number_of_edges(),
        )

        return self._graph

    def _add_entity_node(self, event: CorrelatedEvent) -> None:
        """Add or update a node for the event's entity."""
        entity_id = event.entity_id

        if entity_id in self._graph:
            # Update with max risk and latest timestamp.
            node = self._graph.nodes[entity_id]
            node["risk_score"] = max(node.get("risk_score", 0), event.risk_score)
            node["event_count"] = node.get("event_count", 0) + 1
            ts = node.get("latest_timestamp")
            if ts is None or event.timestamp > ts:
                node["latest_timestamp"] = event.timestamp
            if ts is None or event.timestamp < node.get("earliest_timestamp", event.timestamp):
                node["earliest_timestamp"] = event.timestamp
            if event.mitre_technique:
                techniques = node.get("mitre_techniques", set())
                techniques.add(event.mitre_technique.technique_id)
                node["mitre_techniques"] = techniques
        else:
            self._graph.add_node(
                entity_id,
                risk_score=event.risk_score,
                event_count=1,
                earliest_timestamp=event.timestamp,
                latest_timestamp=event.timestamp,
                event_type=event.event_type,
                mitre_techniques={event.mitre_technique.technique_id} if event.mitre_technique else set(),
            )

    def _infer_temporal_edges(
        self,
        sorted_events: list[CorrelatedEvent],
        window_seconds: float = 300.0,
    ) -> None:
        """Infer causal edges: if entity A's event precedes entity B's event
        within the window, add an edge A → B (A may have caused B).
        """
        for i, event_a in enumerate(sorted_events):
            for j in range(i + 1, len(sorted_events)):
                event_b = sorted_events[j]
                delta = (event_b.timestamp - event_a.timestamp).total_seconds()
                if delta > window_seconds:
                    break  # beyond the window
                if event_a.entity_id == event_b.entity_id:
                    continue  # skip self-loops

                # Add or strengthen the causal edge.
                if self._graph.has_edge(event_a.entity_id, event_b.entity_id):
                    self._graph[event_a.entity_id][event_b.entity_id]["weight"] += 1.0
                else:
                    self._graph.add_edge(
                        event_a.entity_id,
                        event_b.entity_id,
                        weight=1.0,
                        relationship="temporal",
                    )

    def _infer_cooccurrence_edges(
        self,
        sorted_events: list[CorrelatedEvent],
        window_seconds: float = 60.0,
    ) -> None:
        """Add bidirectional co-occurrence edges for entities that appear
        within a tight time window (likely part of the same attack step).
        """
        for i, event_a in enumerate(sorted_events):
            for j in range(i + 1, len(sorted_events)):
                event_b = sorted_events[j]
                delta = (event_b.timestamp - event_a.timestamp).total_seconds()
                if delta > window_seconds:
                    break
                if event_a.entity_id == event_b.entity_id:
                    continue
                # Co-occurrence is bidirectional.
                for src, dst in [(event_a.entity_id, event_b.entity_id), (event_b.entity_id, event_a.entity_id)]:
                    if not self._graph.has_edge(src, dst):
                        self._graph.add_edge(src, dst, weight=0.5, relationship="cooccurrence")
