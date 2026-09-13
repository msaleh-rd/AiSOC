#!/usr/bin/env python3
"""Append a live wet-eval row to the public benchmark scoreboard (Phase B).

``apps/docs/docs/benchmark-scoreboard.mdx`` claims the weekly wet-eval
workflow "opens an auto-PR appending one row to `scoreboard.json`" — before
this script existed, ``.github/workflows/wet-eval.yml`` only rewrote
``benchmark.md`` and never touched ``scoreboard.json``, so that claim was an
OVERCLAIM (see ``docs/audit/REALITY_REPORT.md``: "Public weekly benchmark
scoreboard").

Reads a wet-eval JSON block (produced by ``scripts/run_evals.py --wet
--wet-out``) and appends a new ``substrate:false`` row built from its real
numbers, matching ``scoreboard.schema.json``. Refuses to run against a
``dry_run`` block — only a real live-LLM run (``mode: "live"``) may be
published as ``substrate:false``, so a misconfigured/no-op wet-eval run can
never silently masquerade as live-agent performance. Newest-first: the new
row is inserted at index 0.

Usage::

    python3 scripts/wet_eval_append_scoreboard.py \\
        --wet-block /tmp/wet-eval/wet-block.json \\
        --commit-sha <sha> \\
        --agent-version v7.5.0 \\
        [--scoreboard apps/docs/static/data/scoreboard.json] \\
        [--check]   # validate + print the row that would be appended, no write
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOREBOARD = ROOT / "apps" / "docs" / "static" / "data" / "scoreboard.json"


def _date_from_ran_at(ran_at: str) -> str:
    """``ran_at`` is an ISO-8601 timestamp; the scoreboard row only needs the date."""
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", ran_at or "")
    if match:
        return match.group(1)
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def build_row(block: dict[str, Any], *, agent_version: str, commit_sha: str) -> dict[str, Any]:
    """Build one scoreboard row from a wet-eval JSON block.

    Raises ``ValueError`` if the block isn't a real live run — the whole
    point of this gate is that a dry-run/degraded block can never be
    published as ``substrate:false`` live-agent performance.
    """
    mode = block.get("mode")
    if mode != "live":
        raise ValueError(
            f"refusing to append a scoreboard row from a {mode!r} wet-eval block — "
            "only mode='live' (real LLM calls) may be published as substrate:false"
        )

    incidents = int(block["incidents"])
    tokens_total = block["tokens"]["total"]
    usd = block["usd"]
    latency = block["latency_seconds"]
    date = _date_from_ran_at(block.get("ran_at", ""))

    return {
        "date": date,
        "agent_version": agent_version,
        "commit_sha": commit_sha[:12],
        "substrate": False,
        "eval_mode": "wet-eval-keyword-judge",
        "mitre_accuracy": round(float(block["mitre_accuracy"]), 4),
        "mitre_accuracy_per_template": None,
        "alert_reduction": None,
        "investigation_completeness": None,
        "response_quality": None,
        "playbook_completion_rate": None,
        "mtc_p50_seconds": round(float(latency["p50"]), 2),
        "mtc_p95_seconds": round(float(latency["p95"]), 2),
        "tokens_total": round(tokens_total["mean"] * incidents),
        "usd_total": round(usd["mean"] * incidents, 4),
        "tokens_mean_per_investigation": round(tokens_total["mean"]),
        "usd_mean_per_investigation": round(usd["mean"], 5),
        "rate_card_model": block.get("model", "unknown"),
        "rate_card_dated": date[:7],
        "notes": (
            f"Weekly wet-eval (.github/workflows/wet-eval.yml): real LangGraph "
            f"agent dispatch over {incidents} synthetic incidents, real LLM "
            f"calls ({block.get('model', 'unknown')}), real token/USD/latency. "
            "mitre_accuracy is tactic-set-intersection judging "
            "(wet-eval-keyword-judge), not an LLM-as-judge rubric. "
            f"harness_version={block.get('harness_version', 'unknown')}."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wet-block", required=True, type=Path, help="Path to the wet-eval JSON block")
    parser.add_argument("--commit-sha", required=True, help="Git commit SHA the run was produced against")
    parser.add_argument("--agent-version", required=True, help="Tagged agent version, e.g. v7.5.0")
    parser.add_argument("--scoreboard", type=Path, default=DEFAULT_SCOREBOARD, help="Path to scoreboard.json")
    parser.add_argument("--check", action="store_true", help="print the row that would be appended; don't write")
    args = parser.parse_args()

    block = json.loads(args.wet_block.read_text(encoding="utf-8"))
    try:
        row = build_row(block, agent_version=args.agent_version, commit_sha=args.commit_sha)
    except (ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.check:
        print(json.dumps(row, indent=2))
        return 0

    data = json.loads(args.scoreboard.read_text(encoding="utf-8"))
    data.setdefault("rows", []).insert(0, row)
    args.scoreboard.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Appended scoreboard row for {row['date']} (mitre_accuracy={row['mitre_accuracy']}) to {args.scoreboard}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
