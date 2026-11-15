# STATE
last_updated: 2026-11-15T01:00:00Z
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
    status: TODO
    commit: null
    tests_green: []
    notes: "gate-jcs"
  - id: M0-T03
    status: TODO
    commit: null
    tests_green: []
    notes: "gate-crypto"
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
