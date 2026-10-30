#!/usr/bin/env bash
# Regenerate uv.lock and the pip-compatible hashed lock files.
#
# Edit pyproject.toml for dependency changes, then run this script and commit
# pyproject.toml, uv.lock, requirements.txt and requirements-dev.txt together.
set -euo pipefail
cd "$(dirname "$0")/.."

UV="${UV:-uv}"
if ! command -v "$UV" >/dev/null 2>&1; then
  echo "[lock] uv is required: https://docs.astral.sh/uv/" >&2
  exit 1
fi

echo "[lock] Resolving universal lock"
"$UV" lock

echo "[lock] Exporting runtime lock"
"$UV" export \
  --frozen --quiet --format requirements-txt --no-emit-project --no-dev \
  --output-file requirements.txt

echo "[lock] Exporting development lock"
"$UV" export \
  --frozen --quiet --format requirements-txt --no-emit-project --group dev \
  --output-file requirements-dev.txt

echo "[lock] Updated uv.lock, requirements.txt and requirements-dev.txt"
