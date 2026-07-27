#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3.11}"
WHEELHOUSE="${WHEELHOUSE:-${ROOT_DIR}/wheelhouse}"
PIP_CACHE_DIR="${PIP_CACHE_DIR:-${ROOT_DIR}/.pip-cache}"
export PIP_CACHE_DIR

cd "${ROOT_DIR}"
mkdir -p "${WHEELHOUSE}"
mkdir -p "${PIP_CACHE_DIR}"

"${PYTHON_BIN}" -m pip download \
  --dest "${WHEELHOUSE}" \
  hatchling \
  editables

PIP_FIND_LINKS="${WHEELHOUSE}" \
"${PYTHON_BIN}" -m pip download \
  --dest "${WHEELHOUSE}" \
  ".[dev]"

cat <<EOF
Wheelhouse written to: ${WHEELHOUSE}

Offline install:
  PYTHON=${PYTHON_BIN} WHEELHOUSE=${WHEELHOUSE} ./scripts/install-offline.sh
EOF
