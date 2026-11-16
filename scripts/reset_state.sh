#!/usr/bin/env bash
# Stop experiment traffic and kernel agents before using this helper.
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${P20_PYTHON:-$PROJECT_ROOT/.venv/bin/python}" "$PROJECT_ROOT/scripts/reset_state.py" "$@"
