#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

: "${API_KEY:?API_KEY is required}"
: "${JWT_SECRET:?JWT_SECRET is required}"

BASE_URL="${SECURITY_BASE_URL:-http://127.0.0.1:8080}"
PHASE_A_DURATION="${PHASE_A_DURATION_SEC:-180}"
PHASE_B_DURATION="${PHASE_B_DURATION_SEC:-180}"
SPLIT_DURATION="${PHASE_SPLIT_DURATION_SEC:-600}"

python3 scripts/security/phase_a_strict.py \
  --base-url "$BASE_URL" \
  --duration-sec "$PHASE_A_DURATION" \
  --workers "${PHASE_A_WORKERS:-10}"

python3 scripts/security/phase_b_hostile.py \
  --base-url "$BASE_URL" \
  --duration-sec "$PHASE_B_DURATION" \
  --workers "${PHASE_B_WORKERS:-16}"

python3 scripts/security/phase_10m_split.py \
  --base-url "$BASE_URL" \
  --duration-sec "$SPLIT_DURATION" \
  --workers "${PHASE_SPLIT_WORKERS:-24}" \
  --legit-share "${PHASE_SPLIT_LEGIT_SHARE:-0.45}"

echo "Security cycle completed. Summaries are stored in artifacts/security/."
