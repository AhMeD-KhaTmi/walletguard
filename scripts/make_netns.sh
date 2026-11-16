#!/usr/bin/env bash
# Create the bridge and the client namespaces defined in eval/identities.json.
# Idempotent by construction: existing namespaces/bridge are removed first.
#
#   sudo bash scripts/make_netns.sh
#   bash scripts/make_netns.sh --dry-run        # print the exact ip commands
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/eval/netns.py" apply "$@"
