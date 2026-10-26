#!/usr/bin/env python3
"""Verify exact semantic replay while allowing a separately randomized order."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            key = row["unit"]["unit_id"]
            if key in rows:
                raise ValueError("duplicate unit_id")
            rows[key] = row
    return rows


def semantic(row: dict) -> dict:
    result = row["result"]
    result.pop("derivation_elapsed_ns", None)
    result.pop("crypto_elapsed_ns", None)
    result.pop("total_elapsed_ns", None)
    for side in ("anchor", "comparison"):
        if isinstance(result.get(side), dict):
            result[side].pop("derivation_elapsed_ns", None)
            result[side].pop("crypto_elapsed_ns", None)
            result[side].pop("total_elapsed_ns", None)
            # Go deliberately performs an optional one-byte anti-test-coupling
            # read. The pair worker makes generated blocks invariant to it, so
            # read-count/trace telemetry is diagnostic rather than a protocol
            # artifact and is excluded from semantic replay equality.
            result[side].pop("config_rand_reads", None)
            result[side].pop("config_rand_bytes", None)
            result[side].pop("config_rand_read_sizes", None)
            result[side].pop("config_rand_roles", None)
    return {
        "unit": {k: v for k, v in row["unit"].items() if k != "schedule_index"},
        "observed": row["observed"],
        "expected": row["expected"],
        "expectation_match": row["expectation_match"],
        "result": result,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("primary", type=Path)
    parser.add_argument("replay", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    primary = load(args.primary)
    replay = load(args.replay)
    primary_implementations = sorted({row["result"].get("implementation", "unknown") for row in primary.values()})
    replay_implementations = sorted({row["result"].get("implementation", "unknown") for row in replay.values()})
    missing = sorted(set(primary) - set(replay))
    extra = sorted(set(replay) - set(primary))
    mismatches = sorted(key for key in set(primary) & set(replay) if semantic(primary[key]) != semantic(replay[key]))
    report = {
        "schema_version": "1.0",
        "primary_units": len(primary),
        "replay_units": len(replay),
        "primary_implementations": primary_implementations,
        "replay_implementations": replay_implementations,
        "missing": missing,
        "extra": extra,
        "semantic_mismatches": mismatches,
        "exact_semantic_replay": not missing and not extra and not mismatches,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    # Write canonical UTF-8 bytes so the reported digest is identical on
    # Windows and POSIX hosts (Path.write_text translates newlines on Windows).
    args.output.write_bytes(encoded.encode("utf-8"))
    print(json.dumps({**report, "report_sha256": hashlib.sha256(encoded.encode()).hexdigest()}))
    if not report["exact_semantic_replay"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
