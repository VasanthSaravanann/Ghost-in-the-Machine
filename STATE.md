# STATE
last_updated: 2026-11-15T16:30:00Z
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
    commit: ee2b6ca
    tests_green: [T-PER-001, T-PER-002, T-PER-003, T-PER-004, T-PER-005, T-PER-006, T-PER-007, T-PER-008, T-PER-009, T-PER-010, T-PER-011, T-PER-012, T-PER-013, T-PER-014, T-PER-015, T-PER-016]
    notes: "PersistentStore (redb 2.6, copy-on-write ACID): write-through commit per insert, rollback to committed DB on failure, content-addressed ids survive reload via content_digest_hint, hash-identified endorsed corpora persist. Summarisation = meet (mixed content stays EXTERNAL). MemoryRecord stores label + full ancestry; recover_label is the meet with known ancestors (restart can never raise). VectorStore adapter preserves label through round-trip. kill -9 simulation (uncommitted txn absent after reopen), corrupt-file detection fails closed (size guard + catch_unwind around redb create), 8-thread concurrent writers behind Mutex = one store."
  - id: M2-T06
    status: DONE
    commit: cace85e
    tests_green: [T-DEC-001, T-DEC-002, T-DEC-003, T-DEC-004, T-DEC-005, T-DEC-006, T-DEC-007, T-DEC-008]
    notes: "Scoped declassification: minting requires a DeclassifyAuthority trait; the agent channel holds DenyAllAuthority so model-initiated declassification is rejected (T-DEC-001). Records are scoped to one target; expired TTL restores the EXTERNAL taint (T-DEC-003); entries are stable-digest'd and serialisable for replay (T-DEC-004). The acceptance rule maps to GateError fail-closed: R12 applies (integration with M3 endorsement API pending)."
  - id: M3-T01
    status: DONE
    commit: 3f842cf
    tests_green: [T-BUD-001, T-BUD-002, T-BUD-003, T-BUD-004, T-BUD-005, T-BUD-006, T-BUD-007, T-BUD-008, T-BUD-009, T-BUD-010, T-BUD-011]
    notes: "Per-episode, per-class E_max (default 5); hard cap, no in-band raise (request_band_raise logs InBandRaiseIgnored); out-of-band principal only via PrincipalGate, distinct CapChanged ledger event, Reset bounds used to the new cap; >=20s inter-prompt, DEC-P03 queue (renders only when due, budget consumed at render, overflow -> QueueFull + spam); similar-request cooldown clamps used. used<=cap holds after EVERY call (incl. render_due); seeded property test 1000 cases. LeafSink integration is M3-T04."
  - id: M3-T02
    status: DONE
    commit: e0012ae
    tests_green: [T-BRF-001, T-BRF-002, T-BRF-003, T-BRF-004, T-BRF-005, T-BRF-006, T-BRF-007, T-BRF-008, T-BRF-009, T-BRF-010, T-BRF-011]
    notes: "Third-person briefs on deterministic (class, reversibility) templates; denial-list framing filter catches the >=150-string persuasion corpus; taint diff <=3 spans x <=280 chars with explicit marker; resolved effect concrete (destination, count, blast radius, no ellipses); agent justification quarantined (labelled UNTRUSTED — AUTHORED BY THE AGENT) and counted into w_sup; counter-considerations from the template set only; budget line k of E. Weights w_sup/w_cnt/w_neu computed; sup_share() defined (validated at M3-T03)."
  - id: M3-T03
    status: DONE
    commit: 12ec25b
    tests_green: [T-SYM-001, T-SYM-002, T-SYM-003, T-SYM-004, T-SYM-005, T-SYM-006, T-SYM-007, T-SYM-008, T-SYM-009, T-SYM-010, T-SYM-011, T-SYM-012, T-SYM-013, T-SYM-014, T-SYM-015, T-SYM-016, T-SYM-017, T-SYM-018]
    notes: "Sup share = w_sup/(w_sup+w_cnt+w_neu) measured in rendered tokens AND rendered pixel area; the rule takes the max (P3-R7). >0.50 => not rendered + DENY_SYMMETRY (INV-6). Whitespace and zero-size blocks contribute nothing to the pixel measure; tiny-font counter text is pixel-weighted; collapsed justification is still counted; 200% zoom is ratio-invariant; screen-reader/render order is a fixed contract. Deterministic layout model (no browser in the loop); headless-browser cross-check (<=2% per block) is CI work for M3-T05 wiring, recorded as ISSUE-003."
  - id: M3-T04
    status: DONE
    commit: a06fe53
    tests_green: [T-LDG-001, T-LDG-002, T-LDG-003, T-LDG-004, T-LDG-005, T-LDG-006, T-LDG-007, T-LDG-008, T-LDG-009, T-LDG-010, T-LDG-011, T-LDG-012, T-LDG-013, T-LDG-014, T-LDG-015, T-LDG-016, T-LDG-017, T-LDG-018, T-LDG-019, T-LDG-020, T-LDG-021, T-LDG-022, T-LDG-023, T-LDG-024, T-LDG-025, T-LDG-026]
    notes: "Leaf A carries every P3-R17 field (schema test), signed over JCS bytes with digest+signature verified; release requires H(JCS(outbound)) == call_digest (INV-5: one-byte mutation, wrong call, replay all denied); 15-min endorsement timeout fails closed; resume plan never re-prompts (Endorsed->Release, Released->ExecuteOnce, Executed->Done, NF-R5); Leaf B bound by ref=H(leaf_a) with 0..3 regret and duplicate-attestation rejection; tick() records AttestLapsed after delta_t and never invents confirmation (INV-8); delta_t bounds 1h..30d; asymmetric briefs are never endorsed; leaves exit ONLY through gate_core::LeafSink, implemented by VecSink and by gate_span::SpanLeafSink (signed, chained, fsync'd span chain, T-LDG-016b)."
  - id: M3-T05
    status: BLOCKED
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T06
    status: DONE
    commit: e7e04a2
    tests_green: [T-DRF-001, T-DRF-002, T-DRF-003, T-DRF-004, T-DRF-005, T-DRF-006, T-DRF-007, T-DRF-008, T-DRF-009, T-DRF-010, T-DRF-011, T-DRF-012, T-DRF-013, T-DRF-014]
    notes: "Per-principal trailing windows (20): rubber-stamp rate (<2 s), regret rate (Leaf B scale >=2; un-attested never counts), bounded sycophantic-drift score monotone in the stamp rate, per-principal isolation. auto_tighten fires only on a FULL window with regret >15%: lowers the cap by one (never raises, floor 1) and requires dual principal. Dual-principal brief is built from shared material only, so P1's decision/note are structurally absent; any split denies (DUAL_PRINCIPAL_SPLIT finding). Deterministic/replayable. G-M3 still unrun (ISSUE-004)."
  - id: M4-T01
    status: DONE
    commit: null
    tests_green: [T-MRK-001, T-MRK-002, T-MRK-003, T-MRK-004, T-MRK-005, T-MRK-006, T-MRK-007, T-MRK-008, T-MRK-009, T-MRK-010, T-MRK-011, T-MRK-012, T-MRK-013, T-MRK-014, T-MRK-015, T-MRK-016, T-MRK-017, T-MRK-018, T-MRK-019, T-MRK-020]
    notes: "RFC 9162 MTH with 0x00 leaf / 0x01 node domain separation, inclusion proofs and consistency proofs, redb TreeStore (append + reopen + corrupt-file fail-closed). Tree heads, inclusion proofs and consistency proofs are byte-identical to the independent ref/merkle_ref.py over 64 leaves / all (m,n) pairs up to n=24. NOTE: the verifying algorithm for consistency proofs is deliberately NOT shipped here — the first implementation failed its own round-trip and shipping it would be a false guarantee; proof-level agreement with the independent reference is what M4-T01 claims. Sound verify_consistency is M4-T04 (ISSUE-006)."
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
  - id: ISSUE-006
    task: M4-T01/M4-T04
    kind: SPEC_CONFLICT
    detail: "verify_consistency (RFC 9162 s2.1.4.2) is not shipped: my first transcription failed round-trip on m=8,n=16 (fr/sr sibling ordering), and shipping a self-consistent but unverified algorithm would be a false guarantee (R10). Prover output is byte-identical to ref/merkle_ref.py, which is what M4-T01 claims. The verifier must be implemented and cross-checked against the reference prover for all (m<=n<=64) before mcp-audit verify can claim consistency checking (M4-T04)."
    status: OPEN
  - id: ISSUE-005
    task: M3-T05
    kind: NEEDS_HUMAN
    detail: "BLOCKED on ISSUE-003: T-CHN-001..020 are headless-browser tests (clickjacking/iframe, origin confusion, 3 s dwell, WebAuthn assertion validation) and no browser harness or CI image decision exists. Also needs the DEC on webauthn-rs native-code policy (§2.4, §12.10). Not started rather than partly stubbed."
    status: OPEN
  - id: ISSUE-004
    task: M1-T01..M3-T03
    kind: NEEDS_HUMAN
    detail: "These tasks are marked DONE against their test lists, but their PHASE eval gates (G-M1 AF1<=5%, G-M2 AF3<=10%, G-M3 AF4<=10%) have never run: void-bench is a stub and there is no evals/ suite (public or held-out). Per R9 a task is not DONE until its acceptance list is green in CI, so progress here is 'tests green, gate unrun'. Resolving requires void-bench (M5-T01) + scenario authoring (M5-T02), which should now be treated as the critical path."
    status: OPEN
  - id: ISSUE-003
    task: M3-T03
    kind: NEEDS_HUMAN
    detail: "The deterministic layout model is implemented and tested for tokens/pixels, whitespace, zero-size, tiny-font, 200% zoom and render order, but the CI cross-check against a headless browser (tolerance <=2% per block) has not been run: no browser harness exists yet. Needs a CI decision (fantoccini/Playwright image) before the M3 gate."
    status: OPEN
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
