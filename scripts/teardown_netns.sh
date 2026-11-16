#!/usr/bin/env bash
# Remove the namespaces and bridge created by scripts/make_netns.sh.
# This never touches an unrelated namespace: only names in eval/identities.json
# and the p20br0 bridge are deleted.
#
#   sudo bash scripts/teardown_netns.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/eval/netns.py" cleanup "$@"
