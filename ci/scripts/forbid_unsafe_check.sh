#!/usr/bin/env bash
# T-REPO-004: the decision crates in plan.md §2.0 R5 must carry
# #![forbid(unsafe_code)] (and the workspace also forbids it globally).
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
crates="gate-core gate-jcs gate-crypto gate-span gate-schema gate-policy gate-provenance gate-ledger gate-brief gate-tlog"
bad=0
for c in $crates; do
  f="$root/crates/$c/src/lib.rs"
  if ! grep -q 'forbid(unsafe_code)' "$f" 2>/dev/null; then
    echo "VIOLATION: $c missing forbid(unsafe_code)" >&2
    bad=1
  fi
done
if [ "$bad" -ne 0 ]; then exit 1; fi
echo "forbid-unsafe: clean"
