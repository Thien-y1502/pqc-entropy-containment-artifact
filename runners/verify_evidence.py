#!/usr/bin/env python3
"""Verify bounded P01 evidence envelopes, schedules, records, and summaries."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_RUNS = (
    "go124-primary",
    "go124-replay",
    "xwing-primary",
    "xwing-replay",
    "liboqs-primary",
    "liboqs-replay",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_run(path: Path) -> dict:
    envelope = json.loads((path / "evidence-envelope.json").read_text(encoding="utf-8"))
    if envelope.get("status") != "PASS":
        raise ValueError(f"{path.name}: envelope status is not PASS")
    for name in ("records.jsonl", "schedule.json", "summary.json"):
        actual = sha256(path / name)
        if envelope.get("files", {}).get(name) != actual:
            raise ValueError(f"{path.name}: envelope digest mismatch for {name}")

    schedule = json.loads((path / "schedule.json").read_text(encoding="utf-8"))
    summary = json.loads((path / "summary.json").read_text(encoding="utf-8"))
    records = [json.loads(line) for line in (path / "records.jsonl").read_text(encoding="utf-8").splitlines()]
    scheduled = {unit["unit_id"]: unit for unit in schedule["units"]}
    observed = {row["unit"]["unit_id"]: row for row in records}
    if len(records) != 120 or len(observed) != 120 or len(scheduled) != 120:
        raise ValueError(f"{path.name}: expected 120 unique units")
    if set(observed) != set(scheduled):
        raise ValueError(f"{path.name}: schedule/record unit sets differ")
    for unit_id, row in observed.items():
        if row["unit"] != scheduled[unit_id]:
            raise ValueError(f"{path.name}: scheduled unit differs for {unit_id}")
        if row.get("expectation_match") is not True or row.get("observed") != row.get("expected"):
            raise ValueError(f"{path.name}: frozen expectation failed for {unit_id}")
        if len(row.get("stdout_sha256", "")) != 64:
            raise ValueError(f"{path.name}: invalid stdout digest for {unit_id}")
        for side in ("anchor", "comparison"):
            payload = row.get("result", {}).get(side)
            if isinstance(payload, dict) and "honest_agreement" in payload:
                if payload["honest_agreement"] is not True:
                    raise ValueError(f"{path.name}: KEM agreement failed for {unit_id}/{side}")
    cells = summary.get("cells", {})
    if summary.get("units") != 120 or summary.get("pairs_per_cell") != 8:
        raise ValueError(f"{path.name}: summary count mismatch")
    if summary.get("all_units_match_frozen_expectations") is not True:
        raise ValueError(f"{path.name}: summary expectation gate failed")
    if len(cells) != 15 or any(cell.get("pairs") != 8 for cell in cells.values()):
        raise ValueError(f"{path.name}: incomplete 5x3 response surface")
    if summary.get("implementation") != schedule.get("implementation"):
        raise ValueError(f"{path.name}: implementation identity mismatch")
    return {
        "run": path.name,
        "implementation": summary["implementation"],
        "phase": summary["phase"],
        "units": 120,
        "cells": 15,
        "all_expectations_match": True,
        "envelope_sha256": sha256(path / "evidence-envelope.json"),
        "records_sha256": sha256(path / "records.jsonl"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    runs = [verify_run(args.root / name) for name in EXPECTED_RUNS]
    report = {
        "schema_version": "1.0",
        "status": "PASS",
        "runs": runs,
        "total_executed_units": sum(item["units"] for item in runs),
        "total_response_surface_cells": sum(item["cells"] for item in runs),
        "scope": "3 implementations x primary/replay; integrity and frozen qualitative outcomes",
    }
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if args.output:
        args.output.write_bytes(encoded)
    print(json.dumps({**report, "report_sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    main()
