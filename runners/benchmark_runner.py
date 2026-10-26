#!/usr/bin/env python3
"""Run the frozen P01 process-level cost matrix on Linux."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import tempfile
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


def write_json(path: Path, value: object) -> None:
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def build_units(blocks: int, trial_base: int, schedule_seed: int) -> list[dict]:
    units: list[dict] = []
    rng = random.Random(schedule_seed)
    for block_index in range(blocks):
        cells = [(architecture, recipe) for architecture in ARCHITECTURES for recipe in RECIPES]
        rng.shuffle(cells)
        for order_in_block, (architecture, recipe) in enumerate(cells):
            offset = block_index * 100 + order_in_block * 2
            unit = {
                "block_index": block_index,
                "order_in_block": order_in_block,
                "architecture": architecture,
                "recipe": recipe,
                "anchor_trial": trial_base + offset,
                "comparison_trial": trial_base + offset + 1,
            }
            unit["unit_id"] = sha256_bytes(canonical(unit))[:20]
            units.append(unit)
    return units


class ChildTimeout(Exception):
    pass


def _alarm_handler(_signum: int, _frame: object) -> None:
    raise ChildTimeout()


def run_child(binary: Path, unit: dict, timeout: int) -> dict:
    if os.name != "posix" or not hasattr(os, "wait4"):
        raise RuntimeError("benchmark_runner requires Linux/POSIX wait4 resource accounting")
    command = [
        str(binary),
        "--unit-architecture", unit["architecture"],
        "--unit-recipe", unit["recipe"],
        "--unit-anchor", str(unit["anchor_trial"]),
        "--unit-trial", str(unit["comparison_trial"]),
    ]
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LC_ALL": "C.UTF-8",
    }
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        started = time.monotonic_ns()
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(stdout_file.fileno(), 1)
                os.dup2(stderr_file.fileno(), 2)
                os.execve(str(binary), command, environment)
            finally:
                os._exit(127)
        previous_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(timeout)
        try:
            _, status, usage = os.wait4(pid, 0)
        except ChildTimeout:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise RuntimeError(f"unit {unit['unit_id']} exceeded {timeout}s")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
        elapsed_ns = time.monotonic_ns() - started
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
    exit_code = os.waitstatus_to_exitcode(status)
    if exit_code != 0:
        raise RuntimeError(
            f"unit {unit['unit_id']} child exit {exit_code}; stderr_sha256={sha256_bytes(stderr)}"
        )
    if stderr:
        raise RuntimeError(f"unit {unit['unit_id']} emitted unexpected stderr")
    result = json.loads(stdout)
    if result.get("architecture") != unit["architecture"] or result.get("recipe") != unit["recipe"]:
        raise RuntimeError(f"unit {unit['unit_id']} identity mismatch")
    for side in ("anchor", "comparison"):
        payload = result.get(side)
        if isinstance(payload, dict) and payload.get("honest_agreement") is False:
            raise RuntimeError(f"unit {unit['unit_id']} honest agreement failed on {side}")
    return {
        "unit": unit,
        "wall_time_ns": elapsed_ns,
        "user_cpu_ns": round(usage.ru_utime * 1_000_000_000),
        "system_cpu_ns": round(usage.ru_stime * 1_000_000_000),
        "max_rss_kib": int(usage.ru_maxrss),
        "stdout_sha256": sha256_bytes(stdout),
        "result_identity": {
            "implementation": result.get("implementation"),
            "architecture": result.get("architecture"),
            "recipe": result.get("recipe"),
        },
    }


def run_warmups(binary: Path, count: int, timeout: int) -> list[dict]:
    rows = []
    index = 0
    for architecture in ARCHITECTURES:
        for recipe in RECIPES:
            for repetition in range(count):
                anchor = 900_000 + index * 2
                unit = {
                    "block_index": -1,
                    "order_in_block": index,
                    "architecture": architecture,
                    "recipe": recipe,
                    "anchor_trial": anchor,
                    "comparison_trial": anchor + 1,
                    "warmup_repetition": repetition,
                }
                unit["unit_id"] = sha256_bytes(canonical(unit))[:20]
                rows.append(run_child(binary, unit, timeout))
                index += 1
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=["primary", "replay"], required=True)
    parser.add_argument("--blocks", type=int, default=40)
    parser.add_argument("--warmups-per-cell", type=int, default=2)
    parser.add_argument("--trial-base", type=int, default=100_000)
    parser.add_argument("--schedule-seed", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if not 10 <= args.blocks <= 100:
        raise SystemExit("--blocks must be between 10 and 100")
    if not 0 <= args.warmups_per_cell <= 5:
        raise SystemExit("--warmups-per-cell must be between 0 and 5")
    binary = args.binary.resolve(strict=True)
    contract = args.contract.resolve(strict=True)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)

    schedule = {
        "schema_version": "1.0",
        "contract_id": "P01-PERFORMANCE-V1",
        "implementation": args.implementation,
        "phase": args.phase,
        "blocks": args.blocks,
        "schedule_seed": args.schedule_seed,
        "trial_base": args.trial_base,
        "units": build_units(args.blocks, args.trial_base, args.schedule_seed),
    }
    write_json(output / "schedule.json", schedule)

    warmups = run_warmups(binary, args.warmups_per_cell, args.timeout)
    with (output / "warmup-records.jsonl").open("xb") as handle:
        for row in warmups:
            handle.write(canonical(row) + b"\n")

    records = []
    with (output / "records.jsonl").open("xb") as handle:
        for unit in schedule["units"]:
            row = run_child(binary, unit, args.timeout)
            handle.write(canonical(row) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            records.append(row)

    summary = {
        "schema_version": "1.0",
        "contract_id": "P01-PERFORMANCE-V1",
        "scientific_status": "PROCESS_LEVEL_COST_CHARACTERIZATION",
        "implementation": args.implementation,
        "phase": args.phase,
        "binary_sha256": sha256_file(binary),
        "contract_sha256": sha256_file(contract),
        "blocks": args.blocks,
        "observations": len(records),
        "warmup_observations": len(warmups),
        "complete": len(records) == args.blocks * len(ARCHITECTURES) * len(RECIPES),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
        },
        "limitations": [
            "Process startup is included in every observation.",
            "Measurements describe the pinned container and allocated cloud resources.",
            "No deployment-throughput, primitive-cycle, or universal performance claim is supported.",
        ],
    }
    write_json(output / "summary.json", summary)
    files = {
        name: sha256_file(output / name)
        for name in ("schedule.json", "warmup-records.jsonl", "records.jsonl", "summary.json")
    }
    write_json(
        output / "evidence-envelope.json",
        {"schema_version": "1.0", "status": "PASS" if summary["complete"] else "FAIL", "files": files},
    )
    if not summary["complete"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
