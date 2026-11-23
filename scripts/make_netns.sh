#!/usr/bin/env bash
# Create the bridge and the client namespaces defined in eval/identities.json.
# Apply does not remove existing namespaces or the bridge. Run only after
# checking that the planned names/interfaces are absent and traffic is stopped;
# a second apply is not idempotent. Never use cleanup on an active experiment.
#
#   sudo bash scripts/make_netns.sh
#   bash scripts/make_netns.sh --dry-run        # print the exact ip commands
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/eval/netns.py" apply "$@"
