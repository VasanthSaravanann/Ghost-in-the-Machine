#!/usr/bin/env bash
# §0.6: product crates must not reference evals/ or void_bench.
# Usage: r_grep.sh [root]   (defaults to the repository root)
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
hits=0
while IFS= read -r f; do
  if grep -nE 'evals/|void_bench' "$f" >/dev/null 2>&1; then
    echo "VIOLATION: $f references eval paths (R-grep §0.6)" >&2
    grep -nE 'evals/|void_bench' "$f" >&2 || true
    hits=1
  fi
done < <(find "$root/crates" -path '*/target' -prune -o -name '*.rs' -print 2>/dev/null | grep -v '/tests/' | grep -v 'gate-testkit' | grep -v 'void-bench')
if [ "$hits" -ne 0 ]; then exit 1; fi
echo "r-grep: clean"
