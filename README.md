Inline enforcement proxy at the MCP transport boundary. The model is outside the
trusted computing base; authority is derived from data provenance
(`plan.md` is the build spec and wins over this file).

## Status

| Task | Status | Tests |
|---|---|---|
| M0-T00 workspace + CI + guardrails | DONE | T-REPO-001..006 |
| M0-T01 `gate-core` | DONE | T-CORE-001..012 |
| M0-T02 `gate-jcs` (RFC 8785) | DONE | T-JCS-001..020, T-JCS-V (100k differential) |
| M0-T03 `gate-crypto` | DONE | T-CRY-001..010 (RFC 8032 KATs) |
| M0-T04 `gate-span` | DONE | T-SPAN-001..014 |
| M0-T05 `gate-transport` | DONE | T-TRN-001..020, fuzz `mcp_frame` |
| M1-T01 `gate-policy` DSL + engine | DONE | T-POL-001..020 |
| M1-T02 parameter validators | DONE | T-PAR-001..030 |
| M2-T01 provenance lattice | DONE | T-PRV-001..015 |
| M2-T02 structural taint | DONE | T-TNT-001..020 |
| M2-T03 control-flow taint | DONE | T-CTL-001..012 |
| M2-T04 taint pivot halt | DONE | T-PIV-001..014 |
| M2-T05 provenance persistence | DONE | T-PER-001..016 |
| M2-T06 scoped declassification | DONE | T-DEC-001..008 |
| M3-T01 budget + rate limits | DONE | T-BUD-001..011 |
| M3-T02 brief builder + framing filter | DONE | T-BRF-001..011 |
| M3-T03 Sup-share validator | DONE | T-SYM-001..018 |
| M3-T04 split-leaf ledger | DONE | T-LDG-001..026 |
| M3-T06 drift/regret + dual principal | DONE | T-DRF-001..014 |
| M4-T01 RFC 9162 Merkle tree | DONE | T-MRK-001..020 |
| M3-T05 endorsement channel | BLOCKED (ISSUE-005) | T-CHN-001..020 |
| M0-T06 `mcp-gate` shadow mode + G-M0 | TODO (see ISSUE-002) | T-E2E-001/002/003/006, P-LAT-1 |

`STATE.md` is the authoritative machine-maintained ledger (task, commit, tests,
eval numbers, open issues, pending decisions).

## Build and test

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
bash ci/scripts/check.sh        # local mirror of the CI `fast` tier
```

Fuzzing (`cargo-fuzz`, nightly, separate workspace):

```sh
cargo +nightly fuzz run jcs_parse -- -max_total_time=600
cargo +nightly fuzz run mcp_frame -- -max_total_time=600
```

## Layout

See `plan.md` §2.1. Everything under `crates/` is Rust; `ref/` holds the
non-TCB independent verifier used only for differential tests.

## Human sign-off required

Per plan.md §0.2 R12, `DEC-P01`..`DEC-P04` are recorded in `STATE.md` as
**pending sign-off**; do not treat them as final. `ISSUE-001` (measuring G-M0
`P-LAT-1` on a defined storage profile) is open.

## Enforcement, not convention

- `ci/scripts/r_grep.sh` — product crates may not reference `evals/` or `void_bench`.
- `ci/scripts/tcb_lang_check.py` — walks the real dependency tree of the ten
  decision crates and fails on any native-code dependency (dev-deps excluded).
- `ci/scripts/dep_rule_check.py` — no product crate may depend on `gate-testkit`.
- `ci/scripts/lint_self_test.py` — proves the `unwrap_used` lint fails a build.
- `ci/scripts/forbid_unsafe_check.sh` — R5 crates carry `forbid(unsafe_code)`.

Each of these is covered by a test (`crates/gate-testkit/tests/repo_rules.rs`).
