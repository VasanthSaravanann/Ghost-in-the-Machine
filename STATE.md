# STATE
last_updated: 2026-11-15T02:30:00Z
current_phase: M0

tasks:
  - id: M0-T00
    status: DONE
    commit: null
    tests_green: [T-REPO-001, T-REPO-002, T-REPO-003, T-REPO-004, T-REPO-005, T-REPO-006]
    notes: "workspace (18 crates per §2.1), lints (R7), deny.toml, CI T1-T3 + nightly stubs, r-grep, tcb-lang-check, dep-rule + unwrap self-tests; FakeClock/SeededRng/VectorTool stub"
  - id: M0-T01
    status: DONE
    commit: 0b9253c
    tests_green: [T-CORE-001, T-CORE-002, T-CORE-003, T-CORE-004, T-CORE-005, T-CORE-006, T-CORE-007, T-CORE-008, T-CORE-009, T-CORE-010, T-CORE-011, T-CORE-012]
    notes: "Label/meet lattice, Class, IDs, ReasonCode (closed set), Decision, GateError, failclosed::map_error (single mapping), Clock/Rng traits, IdFactory; gate-testkit now impls Clock/Rng (dev-dep cycle is intentional)"
  - id: M0-T02
    status: DONE
    commit: b3c2e7e
    tests_green: [T-JCS-001, T-JCS-002, T-JCS-003, T-JCS-004, T-JCS-005, T-JCS-006, T-JCS-007, T-JCS-008, T-JCS-009, T-JCS-010, T-JCS-011, T-JCS-012, T-JCS-013, T-JCS-014, T-JCS-015, T-JCS-016, T-JCS-017, T-JCS-018, T-JCS-019, T-JCS-020, T-JCS-V]
    notes: "own parser (dup keys, lone surrogates, DEC-P02 exactness, depth bound), ECMA-262 number serialisation, UTF-16 key sort, C0-only escaping; fuzz/jcs_parse target; ref/jcs_ref.py independent verifier, 100k docs 0 mismatches"
  - id: M0-T03
    status: DONE
    commit: 09c6c82
    tests_green: [T-CRY-001, T-CRY-002, T-CRY-003, T-CRY-004, T-CRY-005, T-CRY-006, T-CRY-007, T-CRY-008, T-CRY-009, T-CRY-010]
    notes: "Ed25519 + ECDSA-P256 (RFC 6979 deterministic, low-S enforced), SHA-256, SuiteId agility, SoftKeyStore, HsmKeyStore stub returning SignerUnavailable. RFC 8032 TEST 1/2 known-answer vectors pass."
  - id: M0-T04
    status: TODO
    commit: null
    tests_green: []
    notes: "gate-span"
  - id: M0-T05
    status: TODO
    commit: null
    tests_green: []
    notes: "gate-transport"
  - id: M0-T06
    status: TODO
    commit: null
    tests_green: []
    notes: "mcp-gate shadow mode"
  - id: M1-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M1-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M1-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M1-T04
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T04
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T05
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M2-T06
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T04
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T05
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T06
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M4-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M4-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M4-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M4-T04
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M5-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M5-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M5-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M6-T01
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M6-T02
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M6-T03
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M6-T04
    status: TODO
    commit: null
    tests_green: []
    notes: ""
  - id: M6-T05
    status: TODO
    commit: null
    tests_green: []
    notes: ""

issues: []
decisions: []
