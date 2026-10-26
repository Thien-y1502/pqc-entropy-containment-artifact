#!/usr/bin/env python3
"""Run the frozen, bounded P01 confirmation matrix one child process per pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import time


ARCHITECTURES = [
    "A0_SHARED",
    "A1_LABEL_ONLY",
    "A2_GLOBAL_SPLIT_SHAM",
    "A3_ROLE_ROUTED",
    "A4_HEDGED",
]
RECIPES = ["nominal", "origin_rng_state_reuse", "origin_rng_and_context_reuse"]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def expected(architecture: str, recipe: str) -> dict[str, bool]:
    if recipe == "nominal":
        return {"origin": True, "peer": True, "hybrid": True}
    if architecture in {"A0_SHARED", "A1_LABEL_ONLY", "A2_GLOBAL_SPLIT_SHAM"}:
        return {"origin": False, "peer": False, "hybrid": False}
    if architecture == "A3_ROLE_ROUTED":
        return {"origin": False, "peer": True, "hybrid": True}
    if architecture == "A4_HEDGED":
        value = recipe == "origin_rng_state_reuse"
        return {"origin": value, "peer": value, "hybrid": value}
    raise ValueError(architecture)


def build_units(pairs: int, anchor_base: int, schedule_seed: int) -> list[dict]:
    units = []
    for architecture in ARCHITECTURES:
        for recipe in RECIPES:
            for pair_index in range(pairs):
                anchor_trial = anchor_base + pair_index * 2
                comparison_trial = anchor_trial + 1
                unit = {
                    "architecture": architecture,
                    "recipe": recipe,
                    "pair_index": pair_index,
                    "anchor_trial": anchor_trial,
                    "comparison_trial": comparison_trial,
                }
                unit["unit_id"] = sha256_bytes(canonical(unit))[:20]
                units.append(unit)
    random.Random(schedule_seed).shuffle(units)
    for index, unit in enumerate(units, 1):
        unit["schedule_index"] = index
    return units


def normalized(result: dict) -> dict[str, bool]:
    peer = result.get("peer_freshness_preserved")
    if peer is None:
        peer = result.get("x25519_freshness_preserved")
    if peer is None:
        peer = result.get("hqc_freshness_preserved")
    return {
        "origin": bool(result["mlkem_freshness_preserved"]),
        "peer": bool(peer),
        "hybrid": bool(result["hybrid_freshness_preserved"]),
    }


def run_unit(binary: Path, unit: dict, timeout: int) -> dict:
    command = [
        str(binary),
        "--unit-architecture", unit["architecture"],
        "--unit-recipe", unit["recipe"],
        "--unit-anchor", str(unit["anchor_trial"]),
        "--unit-trial", str(unit["comparison_trial"]),
    ]
    started = time.monotonic_ns()
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LC_ALL": "C.UTF-8"},
    )
    elapsed_ns = time.monotonic_ns() - started
    if completed.returncode != 0:
        raise RuntimeError(
            f"unit {unit['unit_id']} child exit {completed.returncode}; "
            f"stderr_sha256={sha256_bytes(completed.stderr)}"
        )
    if completed.stderr:
        raise RuntimeError(f"unit {unit['unit_id']} emitted unexpected stderr")
    result = json.loads(completed.stdout)
    if result.get("architecture") != unit["architecture"] or result.get("recipe") != unit["recipe"]:
        raise RuntimeError(f"unit {unit['unit_id']} identity mismatch")
    observed = normalized(result)
    anticipated = expected(unit["architecture"], unit["recipe"])
    return {
        "unit": unit,
        "elapsed_ns": elapsed_ns,
        "stdout_sha256": sha256_bytes(completed.stdout),
        "observed": observed,
        "expected": anticipated,
        "expectation_match": observed == anticipated,
        "result": result,
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=["primary", "replay"], required=True)
    parser.add_argument("--pairs", type=int, default=8)
    parser.add_argument("--anchor-base", type=int, default=1000)
    parser.add_argument("--schedule-seed", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if not 2 <= args.pairs <= 16:
        raise SystemExit("--pairs must be between 2 and 16")
    if args.anchor_base < 1000:
        raise SystemExit("confirmation anchors must be disjoint from the development pilot")
    binary = args.binary.resolve(strict=True)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    units = build_units(args.pairs, args.anchor_base, args.schedule_seed)
    schedule = {
        "schema_version": "1.0",
        "contract_id": "P01-CONFIRMATION-V1",
        "implementation": args.implementation,
        "phase": args.phase,
        "schedule_seed": args.schedule_seed,
        "pairs_per_cell": args.pairs,
        "anchor_base": args.anchor_base,
        "units": units,
    }
    schedule_path = output / "schedule.json"
    write_json(schedule_path, schedule)

    records_path = output / "records.jsonl"
    records = []
    with records_path.open("xb") as handle:
        for unit in units:
            record = run_unit(binary, unit, args.timeout)
            encoded = canonical(record) + b"\n"
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            records.append(record)

    cells = {}
    for architecture in ARCHITECTURES:
        for recipe in RECIPES:
            selected = [
                row for row in records
                if row["unit"]["architecture"] == architecture and row["unit"]["recipe"] == recipe
            ]
            cells[f"{architecture}|{recipe}"] = {
                "pairs": len(selected),
                "origin_freshness_preserved": sum(row["observed"]["origin"] for row in selected),
                "peer_freshness_preserved": sum(row["observed"]["peer"] for row in selected),
                "hybrid_freshness_preserved": sum(row["observed"]["hybrid"] for row in selected),
                "expectation_matches": sum(row["expectation_match"] for row in selected),
            }
    summary = {
        "schema_version": "1.0",
        "contract_id": "P01-CONFIRMATION-V1",
        "scientific_status": "BOUNDED_CONFIRMATION_NOT_FIELD_PREVALENCE",
        "implementation": args.implementation,
        "phase": args.phase,
        "binary_sha256": sha256_file(binary),
        "units": len(records),
        "pairs_per_cell": args.pairs,
        "all_units_match_frozen_expectations": all(row["expectation_match"] for row in records),
        "cells": cells,
        "limitations": [
            "Exact deterministic response-surface confirmation; no population prevalence estimate.",
            "Software-controlled entropy rollback; no physical fault-rate or exploitability claim.",
            "Freshness is tested by artifact equality; IND-CCA security is not experimentally proved.",
            "A4 is an RFC-8937-style prior-art baseline, not a claimed new hedge.",
        ],
    }
    summary_path = output / "summary.json"
    write_json(summary_path, summary)
    envelope = {
        "schema_version": "1.0",
        "status": "PASS" if summary["all_units_match_frozen_expectations"] else "FAIL",
        "files": {
            "schedule.json": sha256_file(schedule_path),
            "records.jsonl": sha256_file(records_path),
            "summary.json": sha256_file(summary_path),
        },
    }
    write_json(output / "evidence-envelope.json", envelope)
    if envelope["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
