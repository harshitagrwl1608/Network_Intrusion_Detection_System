#!/usr/bin/env bash
# =============================================================================
# NetGuard IDS Ground-Truth Benchmark Runner
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

echo "================================================================================"
echo " Starting NetGuard IDS Ground-Truth Benchmark"
echo " Active Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
echo " Starting Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
echo " Python Binary: $(which python3)"
echo " Working Dir: ${REPO_ROOT}"
echo "================================================================================"

python3 "${REPO_ROOT}/scripts/evaluation/run_ground_truth_benchmark.py" \
    --manifest "${REPO_ROOT}/data/external_benchmarks/ground_truth/manifest.csv" \
    --output "${REPO_ROOT}/results/final_ground_truth_benchmark" \
    "$@"
