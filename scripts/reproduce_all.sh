#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${ROOT}/reproduced-results}"
if [[ -e "${OUT}" ]]; then
  echo "Refusing to overwrite existing output: ${OUT}" >&2
  exit 2
fi
mkdir -p "${OUT}/confirmation" "${OUT}/performance"

docker build -f "${ROOT}/docker/Dockerfile.go" -t p01-artifact-go:1.0 "${ROOT}"
docker build -f "${ROOT}/docker/Dockerfile.rust" -t p01-artifact-rust:1.0 "${ROOT}"
docker build -f "${ROOT}/docker/Dockerfile.liboqs" -t p01-artifact-liboqs:1.0 "${ROOT}"

run_confirmation() {
  local image="$1" name="$2" phase="$3" seed="$4"
  docker run --rm --mount "type=bind,source=${OUT}/confirmation,target=/data" "${image}" \
    --output-dir "/data/${name}" --phase "${phase}" --pairs 8 --anchor-base 1000 --schedule-seed "${seed}"
}
run_confirmation p01-artifact-go:1.0 go124-primary primary 2026102511
run_confirmation p01-artifact-go:1.0 go124-replay replay 2026102521
run_confirmation p01-artifact-rust:1.0 xwing-primary primary 2026102512
run_confirmation p01-artifact-rust:1.0 xwing-replay replay 2026102522
run_confirmation p01-artifact-liboqs:1.0 liboqs-primary primary 2026102513
run_confirmation p01-artifact-liboqs:1.0 liboqs-replay replay 2026102523

python3 "${ROOT}/runners/verify_evidence.py" "${OUT}/confirmation" --output "${OUT}/confirmation/evidence-integrity.json"
python3 "${ROOT}/runners/compare_replay.py" "${OUT}/confirmation/go124-primary/records.jsonl" "${OUT}/confirmation/go124-replay/records.jsonl" "${OUT}/confirmation/go124-replay-check.json"
python3 "${ROOT}/runners/compare_replay.py" "${OUT}/confirmation/xwing-primary/records.jsonl" "${OUT}/confirmation/xwing-replay/records.jsonl" "${OUT}/confirmation/xwing-replay-check.json"
python3 "${ROOT}/runners/compare_replay.py" "${OUT}/confirmation/liboqs-primary/records.jsonl" "${OUT}/confirmation/liboqs-replay/records.jsonl" "${OUT}/confirmation/liboqs-replay-check.json"

run_performance() {
  local image="$1" implementation="$2" name="$3" phase="$4" seed="$5" base="$6"
  docker run --rm --entrypoint python \
    --mount "type=bind,source=${OUT}/performance,target=/data" "${image}" \
    /opt/p01/benchmark_runner.py --binary /opt/p01/pair-worker \
    --implementation "${implementation}" --contract /opt/p01/performance_contract.frozen.json \
    --output-dir "/data/${name}" --phase "${phase}" --blocks 40 --warmups-per-cell 2 \
    --trial-base "${base}" --schedule-seed "${seed}"
}
run_performance p01-artifact-go:1.0 go-crypto-tls-go1.24.13 go124-primary primary 2026102601 100000
run_performance p01-artifact-go:1.0 go-crypto-tls-go1.24.13 go124-replay replay 2026102611 200000
run_performance p01-artifact-rust:1.0 rustcrypto-x-wing xwing-primary primary 2026102602 300000
run_performance p01-artifact-rust:1.0 rustcrypto-x-wing xwing-replay replay 2026102612 400000
run_performance p01-artifact-liboqs:1.0 liboqs-dual-pqc liboqs-primary primary 2026102603 500000
run_performance p01-artifact-liboqs:1.0 liboqs-dual-pqc liboqs-replay replay 2026102613 600000

python3 "${ROOT}/runners/analyze_performance.py" "${OUT}/performance" "${OUT}/performance-analysis"
CHECKSUM_TMP="$(mktemp)"
find "${OUT}" -type f ! -name CHECKSUMS.sha256 -print0 | sort -z | xargs -0 sha256sum > "${CHECKSUM_TMP}"
mv "${CHECKSUM_TMP}" "${OUT}/CHECKSUMS.sha256"
echo "Reproduction complete: ${OUT}"
