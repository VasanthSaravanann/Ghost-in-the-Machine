#!/usr/bin/env bash
# Local mirror of the `fast` CI tier (plan.md §7).
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test -p gate-crypto --features fips
bash ci/scripts/r_grep.sh
bash ci/scripts/forbid_unsafe_check.sh
python3 ci/scripts/tcb_lang_check.py
if command -v cargo-deny >/dev/null 2>&1; then cargo deny check; else echo "cargo-deny: not installed (CI installs it)"; fi
if command -v cargo-audit >/dev/null 2>&1; then cargo audit; else echo "cargo-audit: not installed (CI installs it)"; fi
