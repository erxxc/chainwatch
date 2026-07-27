#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3.11}"
WHEELHOUSE="${WHEELHOUSE:-${ROOT_DIR}/wheelhouse}"
VENV_DIR="${VENV_DIR:-${ROOT_DIR}/.venv}"
PIP_CACHE_DIR="${PIP_CACHE_DIR:-${ROOT_DIR}/.pip-cache}"
export PIP_CACHE_DIR

if [[ ! -d "${WHEELHOUSE}" ]]; then
  echo "wheelhouse not found: ${WHEELHOUSE}" >&2
  echo "Build it during an online window with ./scripts/build-wheelhouse.sh" >&2
  exit 1
fi

cd "${ROOT_DIR}"
mkdir -p "${PIP_CACHE_DIR}"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install \
  --no-index \
  --find-links "${WHEELHOUSE}" \
  hatchling \
  editables

"${VENV_DIR}/bin/python" -m pip install \
  --no-index \
  --find-links "${WHEELHOUSE}" \
  --no-build-isolation \
  -e ".[dev]"

cat <<EOF
Offline environment ready: ${VENV_DIR}

Checks:
  ${VENV_DIR}/bin/python -m pytest
  ${VENV_DIR}/bin/python -m ruff check .
  ${VENV_DIR}/bin/python -m mypy src
EOF
