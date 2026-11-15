# STATE
last_updated: 2026-11-15T09:00:00Z
current_phase: M0

tasks:
  - id: M0-T00
    status: DONE
    commit: e386724
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
    status: DONE
    commit: f12dd67
    tests_green: [T-SPAN-001, T-SPAN-002, T-SPAN-003, T-SPAN-004, T-SPAN-005, T-SPAN-006, T-SPAN-007, T-SPAN-008, T-SPAN-009, T-SPAN-010, T-SPAN-011, T-SPAN-012, T-SPAN-013, T-SPAN-014]
    notes: "JCS-signed spans over Ed25519, per-episode hash chain, length-prefixed fsync'd segment log, append_batch (group commit) behind DEC-P01, injectable Fsync proves effect is withheld until durable, exporter-loss maps through failclosed, OTel-GenAI/MCP attribute schema. Storage profile for P-LAT-1: local APFS SSD, not yet measured."
  - id: M0-T05
    status: DONE
    commit: 725500e
    tests_green: [T-TRN-001, T-TRN-002, T-TRN-003, T-TRN-004, T-TRN-005, T-TRN-006, T-TRN-007, T-TRN-008, T-TRN-009, T-TRN-010, T-TRN-011, T-TRN-012, T-TRN-013, T-TRN-014, T-TRN-015, T-TRN-016, T-TRN-017, T-TRN-018, T-TRN-019, T-TRN-020]
    notes: "MCP JSON-RPC framing (bounded line reader, batch split, strict jsonrpc 2.0, id typing), stdio shim (byte-identical pass-through, per-element batch mediation, no invented notification responses, duplicate/out-of-order correlation, unsolicited server request denial), HTTP/1.1 reverse proxy (timeouts, header/body caps, chunked request decode, JSON body mediation, 403 before upstream contact, SSE/chunked response streaming with flush). fuzz/mcp_frame target. T-TRN-020: 0.036 us/message framing+mediation on this host (not the G-M0 gate)."
  - id: M0-T06
    status: TODO
    commit: null
    tests_green: []
    notes: "mcp-gate shadow mode"
  - id: M1-T01
    status: DONE
    commit: 31fb39e
    tests_green: [T-POL-001, T-POL-002, T-POL-003, T-POL-004, T-POL-005, T-POL-006, T-POL-007, T-POL-008, T-POL-009, T-POL-010, T-POL-011, T-POL-012, T-POL-013, T-POL-014, T-POL-015, T-POL-016, T-POL-017, T-POL-018, T-POL-019, T-POL-020]
    notes: "Strict TOML parser: unknown keys, missing class/pin, invalid regex, unbounded limits, non-closed fail_mode and default_deny=false are all rejected. Pin = sha256:<64 lowercase hex>. Policy hash = sha256(JCS(parsed policy)), order-insensitive. PolicyEngine::decide does pin + strict allowlist (deny, never strip); value validators land in M1-T02. Pulled ahead of M0-T06 (DEC-005)."
  - id: M1-T02
    status: DONE
    commit: da4176b
    tests_green: [T-PAR-001, T-PAR-002, T-PAR-003, T-PAR-004, T-PAR-005, T-PAR-006, T-PAR-007, T-PAR-008, T-PAR-009, T-PAR-010, T-PAR-011, T-PAR-012, T-PAR-013, T-PAR-014, T-PAR-015, T-PAR-016, T-PAR-017, T-PAR-018, T-PAR-019, T-PAR-020, T-PAR-021, T-PAR-022, T-PAR-023, T-PAR-024, T-PAR-025, T-PAR-026, T-PAR-027, T-PAR-028, T-PAR-029, T-PAR-030]
    notes: "Strict allowlist (deny, never strip), regex (linear, ReDoS corpus <10 ms), enum, inclusive numeric range, segment-aware path prefix with confusable/control rejection, injected PathResolver (LexicalResolver for pure tests, FsResolver canonicalises symlinks and new files through the parent), ASCII-only URL host allowlist (no userinfo, rejects IDN homographs, rejects nested redirect URLs), max_len/max_items exact boundaries, null-vs-absent and all type-confusion cases deny. PolicyEngine now REQUIRES a resolver (no insecure default); mcp-gate must inject FsResolver."
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
    status: DONE
    commit: 486aac3
    tests_green: [T-PRV-001, T-PRV-002, T-PRV-003, T-PRV-004, T-PRV-005, T-PRV-006, T-PRV-007, T-PRV-008, T-PRV-009, T-PRV-010, T-PRV-011, T-PRV-012, T-PRV-013, T-PRV-014, T-PRV-015]
    notes: "Label lattice via gate-core::meet; append-only DAG (unknown parent rejected, cycles impossible); content-addressed ids (parent-order independent, idempotent); per-turn windows; hash-identified endorsed corpora with tamper demotion to EXTERNAL_UNTRUSTED_DATA; over-claiming a label is ProvenanceError::TaintRaised. Kani harness formal/lattice_monotone.rs still TODO (M6-T01)."
  - id: M2-T02
    status: DONE
    commit: 19ca93c
    tests_green: [T-TNT-001, T-TNT-002, T-TNT-003, T-TNT-004, T-TNT-005, T-TNT-006, T-TNT-007, T-TNT-008, T-TNT-009, T-TNT-010, T-TNT-011, T-TNT-012, T-TNT-013, T-TNT-014, T-TNT-015, T-TNT-016, T-TNT-017, T-TNT-018, T-TNT-019, T-TNT-020]
    notes: "Structural taint: any untrusted segment in a turn window taints every output of that turn. TaintScorer may only add taint (ancestry meet dominates). Laundering corpus in gate-testkit: 200+ transforms (summarise 1..40, truncate 1..40, 5 case x 8 wrappers, 40 synonym swaps, 40 homoglyph/zero-width insertions, 40 encodings/chunkings); every transform that claims clean provenance is rejected with TaintRaised and honest derivation stays EXTERNAL_UNTRUSTED_DATA. 0 launders."
  - id: M2-T03
    status: DONE
    commit: 19ca93c
    tests_green: [T-CTL-001, T-CTL-002, T-CTL-003, T-CTL-004, T-CTL-005, T-CTL-006, T-CTL-007, T-CTL-008, T-CTL-009, T-CTL-010, T-CTL-011, T-CTL-012]
    notes: "Control-flow taint: untrusted segment in the preceding window taints the call unless screened by a principal-only checkpoint. TaintPath explains from the least-trusted root (ticket #8841, line 14), bounded to 3 hops / 280 chars with an explicit omitted-hop count, stable sha256 digest."
  - id: M2-T04
    status: DONE
    commit: b701b6c
    tests_green: [T-PIV-001, T-PIV-002, T-PIV-003, T-PIV-004, T-PIV-005, T-PIV-006, T-PIV-007, T-PIV-008, T-PIV-009, T-PIV-010, T-PIV-011, T-PIV-012, T-PIV-013, T-PIV-014]
    notes: "PolicyEngine::decide now halts tainted privileged calls: PivotMode::Deny (default, pre-M3) returns DENY_TAINT_PIVOT, PivotMode::Escalate returns ESCALATE_ENDORSEMENT_REQUIRED. READ_ONLY exempt; STATUS: IRREVERSIBLE clean allowed; PRIVILEGE_GRANTING untrusted escalates and blanket_allow is unrepresentable. CallRequest::with_taint merges the path hops into the AuthClosure. Model text never enters the decision (T-PIV-011). M3-T01 flips the default to Escalate and enforces E_max."
  - id: M2-T05
    status: DONE
    commit: null
    tests_green: [T-PER-001, T-PER-002, T-PER-003, T-PER-004, T-PER-005, T-PER-006, T-PER-007, T-PER-008, T-PER-009, T-PER-010, T-PER-011, T-PER-012, T-PER-013, T-PER-014, T-PER-015, T-PER-016]
    notes: "PersistentStore (redb 2.6, copy-on-write ACID): write-through commit per insert, rollback to committed DB on failure, content-addressed ids survive reload via content_digest_hint, hash-identified endorsed corpora persist. Summarisation = meet (mixed content stays EXTERNAL). MemoryRecord stores label + full ancestry; recover_label is the meet with known ancestors (restart can never raise). VectorStore adapter preserves label through round-trip. kill -9 simulation (uncommitted txn absent after reopen), corrupt-file detection fails closed (size guard + catch_unwind around redb create), 8-thread concurrent writers behind Mutex = one store."
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

issues:
  - id: ISSUE-002
    task: M0-T06
    kind: SPEC_CONFLICT
    detail: "M0-T06 lists T-E2E-001..006. After DEC-005 and M2-T01..T04 the taint path is real, so T-E2E-003 (injection -> taint path -> blocked effect) is now implementable. T-E2E-004 (approve with a balanced brief -> executes once -> Leaf A+B) still needs M3-T02..T04. M0-T06 can satisfy T-E2E-001/002/003/006 plus CLI/config/P-LAT-1; T-E2E-004/005 remain blocked on M3."
    status: OPEN
  - id: ISSUE-001
    task: M0-T06
    kind: NEEDS_HUMAN
    detail: "G-M0 (P-LAT-1 p99 <= 15 ms with durable commit) needs a storage profile decision (DEC-P01/§12.11) and a benchmark host. Not measurable on this laptop reproducibly."
    status: OPEN
decisions:
  - id: DEC-005
    summary: "M1-T01 and M1-T02 are implemented before M0-T06."
    rationale: "M0-T06's T-E2E cases need a real policy engine (ISSUE-002). Reordering the dependency graph, not weakening any test. M0-T06 is now blocked only on M2-T01..T04 (taint) and M3-T04 (endorsement)."
  - id: DEC-P01
    summary: "Group commit with bounded batch window; synchronous durable commit before release for every class with an external side effect; READ_ONLY flushed asynchronously with bounded lag."
    rationale: "Proposed in plan.md §0.7. Implemented as SegmentLog::append (sync durable) and SegmentLog::append_batch (one fsync per batch). PENDING HUMAN SIGN-OFF (R12): append_batch is not used by any default code path, and P-LAT-1 has not been measured."
  - id: DEC-P02
    summary: "gate-jcs rejects integer literals not exactly representable as IEEE 754 doubles."
    rationale: "Implemented and tested (T-JCS-007). PENDING HUMAN SIGN-OFF (R12)."
  - id: DEC-P03
    summary: "Rate-limited prompts are queued (max depth N) and consume budget only when rendered; overflow denies."
    rationale: "Not yet implemented (M3-T01/T-BUD-005). PENDING HUMAN SIGN-OFF (R12)."
  - id: DEC-P04
    summary: "Own STH format and witness/cosignature protocol rather than an existing community specification."
    rationale: "Not yet evaluated (M4-T03). PENDING HUMAN SIGN-OFF (R12); no witness code has been written."
