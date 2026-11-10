#!/usr/bin/env bash
# =============================================================================
# NetGuard Real-World PCAP Evaluation Runner
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

echo "================================================================================"
echo " Starting NetGuard IDS Real-World PCAP Evaluation Suite"
echo " Active Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
echo " Starting Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
echo " Python Binary: $(which python3)"
echo " Working Dir: ${REPO_ROOT}"
echo "================================================================================"

python3 "${REPO_ROOT}/scripts/evaluation/run_real_world_evaluation.py" "$@"
