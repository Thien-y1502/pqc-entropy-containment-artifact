#!/usr/bin/env python3
"""Verify and analyze the frozen P01 process-level cost experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
import statistics


RUNS = (
    "go124-primary",
    "go124-replay",
    "xwing-primary",
    "xwing-replay",
    "liboqs-primary",
    "liboqs-replay",
)
ARCHITECTURES = ["A0_SHARED", "A1_LABEL_ONLY", "A2_GLOBAL_SPLIT_SHAM", "A3_ROLE_ROUTED", "A4_HEDGED"]
RECIPES = ["nominal", "origin_rng_state_reuse", "origin_rng_and_context_reuse"]
COMPARISONS = [("A3_ROLE_ROUTED", "A0_SHARED"), ("A4_HEDGED", "A0_SHARED"), ("A4_HEDGED", "A3_ROLE_ROUTED")]
METRICS = ("wall_time_ns", "cpu_time_ns", "max_rss_kib")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    location = (len(ordered) - 1) * probability
    lower = int(location)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = location - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_median(values: list[float], seed: int, resamples: int = 10_000) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(values)
    draws = [statistics.median(values[rng.randrange(n)] for _ in range(n)) for _ in range(resamples)]
    return percentile(draws, 0.025), percentile(draws, 0.975)


def verify_run(path: Path) -> tuple[dict, list[dict]]:
    envelope = json.loads((path / "evidence-envelope.json").read_text(encoding="utf-8"))
    if envelope.get("status") != "PASS":
        raise ValueError(f"{path.name}: evidence envelope is not PASS")
    for name, expected in envelope["files"].items():
        if sha256(path / name) != expected:
            raise ValueError(f"{path.name}: digest mismatch for {name}")
    schedule = json.loads((path / "schedule.json").read_text(encoding="utf-8"))
    summary = json.loads((path / "summary.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (path / "records.jsonl").read_text(encoding="utf-8").splitlines()]
    if summary.get("complete") is not True or summary.get("blocks") != 40 or len(rows) != 600:
        raise ValueError(f"{path.name}: incomplete frozen run")
    scheduled = {row["unit_id"] for row in schedule["units"]}
    observed = {row["unit"]["unit_id"] for row in rows}
    if len(observed) != 600 or observed != scheduled:
        raise ValueError(f"{path.name}: schedule/records mismatch")
    block_cells: dict[int, set[tuple[str, str]]] = {}
    for row in rows:
        row["cpu_time_ns"] = row["user_cpu_ns"] + row["system_cpu_ns"]
        unit = row["unit"]
        block_cells.setdefault(unit["block_index"], set()).add((unit["architecture"], unit["recipe"]))
    expected_cells = {(architecture, recipe) for architecture in ARCHITECTURES for recipe in RECIPES}
    if set(block_cells) != set(range(40)) or any(cells != expected_cells for cells in block_cells.values()):
        raise ValueError(f"{path.name}: incomplete randomized block")
    return summary, rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    cell_rows = []
    contrast_rows = []
    run_metadata = []
    for run_index, run_name in enumerate(RUNS):
        summary, rows = verify_run(args.root / run_name)
        run_metadata.append({
            "run": run_name,
            "implementation": summary["implementation"],
            "phase": summary["phase"],
            "binary_sha256": summary["binary_sha256"],
            "contract_sha256": summary["contract_sha256"],
            "evidence_envelope_sha256": sha256(args.root / run_name / "evidence-envelope.json"),
        })
        implementation = summary["implementation"]
        phase = summary["phase"]
        indexed = {
            (row["unit"]["block_index"], row["unit"]["architecture"], row["unit"]["recipe"]): row
            for row in rows
        }
        for architecture in ARCHITECTURES:
            for recipe in RECIPES:
                selected = [indexed[(block, architecture, recipe)] for block in range(40)]
                for metric in METRICS:
                    values = [float(row[metric]) for row in selected]
                    cell_rows.append({
                        "implementation": implementation,
                        "phase": phase,
                        "architecture": architecture,
                        "recipe": recipe,
                        "metric": metric,
                        "n_blocks": 40,
                        "median": statistics.median(values),
                        "p95": percentile(values, 0.95),
                        "minimum": min(values),
                        "maximum": max(values),
                    })
        for recipe in RECIPES:
            for treatment, baseline in COMPARISONS:
                for metric_index, metric in enumerate(METRICS):
                    treatment_values = [float(indexed[(block, treatment, recipe)][metric]) for block in range(40)]
                    baseline_values = [float(indexed[(block, baseline, recipe)][metric]) for block in range(40)]
                    differences = [a - b for a, b in zip(treatment_values, baseline_values)]
                    ratios = [a / b for a, b in zip(treatment_values, baseline_values) if b > 0]
                    seed = 20261026 + run_index * 100 + metric_index * 10 + len(contrast_rows)
                    diff_low, diff_high = bootstrap_median(differences, seed)
                    ratio_low, ratio_high = bootstrap_median(ratios, seed + 1)
                    contrast_rows.append({
                        "implementation": implementation,
                        "phase": phase,
                        "recipe": recipe,
                        "treatment": treatment,
                        "baseline": baseline,
                        "metric": metric,
                        "n_paired_blocks": 40,
                        "median_difference": statistics.median(differences),
                        "difference_ci95_low": diff_low,
                        "difference_ci95_high": diff_high,
                        "median_ratio": statistics.median(ratios),
                        "ratio_ci95_low": ratio_low,
                        "ratio_ci95_high": ratio_high,
                    })

    def write_csv(name: str, rows: list[dict]) -> None:
        with (args.output / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    write_csv("cell_summary.csv", cell_rows)
    write_csv("paired_contrasts.csv", contrast_rows)
    result = {
        "schema_version": "1.0",
        "contract_id": "P01-PERFORMANCE-V1",
        "status": "PASS",
        "scope": "process-level container cost characterization; 3 implementations x 2 phases x 40 randomized complete blocks",
        "total_measured_observations": 3600,
        "run_metadata": run_metadata,
        "analysis": {
            "paired_block_median": True,
            "bootstrap_resamples": 10000,
            "confidence_level": 0.95,
            "null_hypothesis_tests": "not used",
        },
        "limitations": [
            "Process startup is included.",
            "Container scheduling noise is not a field deployment distribution.",
            "Results do not establish security superiority or a production API recommendation.",
        ],
    }
    (args.output / "performance_analysis.json").write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    manifest = {
        "schema_version": "1.0",
        "files": {
            name: sha256(args.output / name)
            for name in ("cell_summary.csv", "paired_contrasts.csv", "performance_analysis.json")
        },
    }
    (args.output / "analysis-envelope.json").write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({**result, "analysis_envelope_sha256": sha256(args.output / "analysis-envelope.json")}))


if __name__ == "__main__":
    main()
