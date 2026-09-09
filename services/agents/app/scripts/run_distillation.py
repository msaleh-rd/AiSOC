#!/usr/bin/env python3
"""Standalone distillation runner — schedulable via cron or APScheduler.

Usage::

    python -m app.scripts.run_distillation [--tenant-id <id>]

Without ``--tenant-id`` it uses the default tenant from env.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import structlog

logger = structlog.get_logger()


async def _run(tenant_id: str) -> None:
    from app.memory.distillation import compounding_memory

    logger.info("distillation.starting", tenant_id=tenant_id)
    report = await compounding_memory.distill(tenant_id)
    logger.info(
        "distillation.complete",
        signatures_processed=report.signatures_processed,
        priors_count=len(report.priors),
    )
    for sig, prior in report.priors.items():
        logger.info(
            "distillation.prior",
            signature=sig,
            total=prior.total_count,
            fp_count=prior.false_positive_count,
            fp_rate=f"{prior.false_positive_rate:.2%}",
            prior_confidence=f"{prior.prior_confidence:.2f}",
            exemplars=len(prior.exemplar_investigation_ids),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run compounding memory distillation")
    parser.add_argument(
        "--tenant-id",
        default=os.getenv("AISOC_DEFAULT_TENANT", "default"),
        help="Tenant ID to distill (default: $AISOC_DEFAULT_TENANT or 'default')",
    )
    args = parser.parse_args()
    asyncio.run(_run(args.tenant_id))


if __name__ == "__main__":
    main()
