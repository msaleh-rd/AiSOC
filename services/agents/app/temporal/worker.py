"""Temporal worker process — consumes the ``aisoc-investigations`` task queue.

Run with ``python -m app.temporal.worker`` (mirrors ``app.scripts.serve``'s
role as a separate process entrypoint). Requires the optional ``temporal``
extra (``poetry install -E temporal``) and a reachable Temporal server — see
the ``temporal`` / ``temporal-admin-tools`` services gated behind the
``temporal`` Docker Compose profile.
"""

from __future__ import annotations

import asyncio

import structlog

logger = structlog.get_logger()


async def _main() -> None:
    from temporalio.client import Client
    from temporalio.worker import Worker

    from app.temporal.activities import (
        auto_triage_activity,
        compress_events_activity,
        finalize_response_activity,
        gather_evidence_activity,
        perform_rca_activity,
        record_ledger_event_activity,
        run_swarm_activity,
        triage_activity,
    )
    from app.temporal.client import TASK_QUEUE, temporal_target_host
    from app.temporal.workflows import InvestigationWorkflow

    client = await Client.connect(temporal_target_host())
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[InvestigationWorkflow],
        activities=[
            auto_triage_activity,
            triage_activity,
            gather_evidence_activity,
            compress_events_activity,
            run_swarm_activity,
            perform_rca_activity,
            finalize_response_activity,
            record_ledger_event_activity,
        ],
    )
    logger.info("temporal.worker.starting", task_queue=TASK_QUEUE, host=temporal_target_host())
    await worker.run()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
