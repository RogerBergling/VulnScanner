#!/usr/bin/env bash
# Verify that uv.lock and the exported pip lock files are current.
# Intended for CI and pre-release checks.
set -euo pipefail
cd "$(dirname "$0")/.."

UV="${UV:-uv}"
if ! command -v "$UV" >/dev/null 2>&1; then
  echo "[check] uv is required: https://docs.astral.sh/uv/" >&2
  exit 1
fi

"$UV" lock --check
"$UV" export \
  --frozen --quiet --format requirements-txt --no-emit-project --no-dev \
  --output-file requirements.txt
"$UV" export \
  --frozen --quiet --format requirements-txt --no-emit-project --group dev \
  --output-file requirements-dev.txt

if ! git diff --exit-code -- uv.lock requirements.txt requirements-dev.txt; then
  echo "[check] Lock files were stale; run scripts/lock-dependencies.sh and commit the result." >&2
  exit 1
fi

echo "[check] Lock files are current."
