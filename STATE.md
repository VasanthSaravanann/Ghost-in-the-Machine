# STATE
last_updated: 2026-11-16T02:30:00Z
current_phase: M0

tasks:
  - id: M0-T00
    status: DONE
    tier: PC
    commit: e386724
    tests_green: [T-REPO-001, T-REPO-002, T-REPO-003, T-REPO-004, T-REPO-005, T-REPO-006]
    notes: "workspace (18 crates per §2.1), lints (R7), deny.toml, CI T1-T3 + nightly stubs, r-grep, tcb-lang-check, dep-rule + unwrap self-tests; FakeClock/SeededRng/VectorTool stub"
  - id: M0-T01
    status: DONE
    tier: PC
    commit: 0b9253c
    tests_green: [T-CORE-001, T-CORE-002, T-CORE-003, T-CORE-004, T-CORE-005, T-CORE-006, T-CORE-007, T-CORE-008, T-CORE-009, T-CORE-010, T-CORE-011, T-CORE-012]
    notes: "Label/meet lattice, Class, IDs, ReasonCode (closed set), Decision, GateError, failclosed::map_error (single mapping), Clock/Rng traits, IdFactory; gate-testkit now impls Clock/Rng (dev-dep cycle is intentional)"
  - id: M0-T02
    status: DONE
    tier: PC
    commit: b3c2e7e
    tests_green: [T-JCS-001, T-JCS-002, T-JCS-003, T-JCS-004, T-JCS-005, T-JCS-006, T-JCS-007, T-JCS-008, T-JCS-009, T-JCS-010, T-JCS-011, T-JCS-012, T-JCS-013, T-JCS-014, T-JCS-015, T-JCS-016, T-JCS-017, T-JCS-018, T-JCS-019, T-JCS-020, T-JCS-V]
    notes: "own parser (dup keys, lone surrogates, DEC-P02 exactness, depth bound), ECMA-262 number serialisation, UTF-16 key sort, C0-only escaping; fuzz/jcs_parse target; ref/jcs_ref.py independent verifier, 100k docs 0 mismatches"
  - id: M0-T03
    status: DONE
    tier: PC
    commit: 09c6c82
    tests_green: [T-CRY-001, T-CRY-002, T-CRY-003, T-CRY-004, T-CRY-005, T-CRY-006, T-CRY-007, T-CRY-008, T-CRY-009, T-CRY-010]
    notes: "Ed25519 + ECDSA-P256 (RFC 6979 deterministic, low-S enforced), SHA-256, SuiteId agility, SoftKeyStore, HsmKeyStore stub returning SignerUnavailable. RFC 8032 TEST 1/2 known-answer vectors pass."
  - id: M0-T04
    status: DONE
    tier: PC
    commit: f12dd67
    tests_green: [T-SPAN-001, T-SPAN-002, T-SPAN-003, T-SPAN-004, T-SPAN-005, T-SPAN-006, T-SPAN-007, T-SPAN-008, T-SPAN-009, T-SPAN-010, T-SPAN-011, T-SPAN-012, T-SPAN-013, T-SPAN-014]
    notes: "JCS-signed spans over Ed25519, per-episode hash chain, length-prefixed fsync'd segment log, append_batch (group commit) behind DEC-P01, injectable Fsync proves effect is withheld until durable, exporter-loss maps through failclosed, OTel-GenAI/MCP attribute schema. Storage profile for P-LAT-1: local APFS SSD, not yet measured."
  - id: M0-T05
    status: DONE
    tier: PC
    commit: 725500e
    tests_green: [T-TRN-001, T-TRN-002, T-TRN-003, T-TRN-004, T-TRN-005, T-TRN-006, T-TRN-007, T-TRN-008, T-TRN-009, T-TRN-010, T-TRN-011, T-TRN-012, T-TRN-013, T-TRN-014, T-TRN-015, T-TRN-016, T-TRN-017, T-TRN-018, T-TRN-019, T-TRN-020]
    notes: "MCP JSON-RPC framing (bounded line reader, batch split, strict jsonrpc 2.0, id typing), stdio shim (byte-identical pass-through, per-element batch mediation, no invented notification responses, duplicate/out-of-order correlation, unsolicited server request denial), HTTP/1.1 reverse proxy (timeouts, header/body caps, chunked request decode, JSON body mediation, 403 before upstream contact, SSE/chunked response streaming with flush). fuzz/mcp_frame target. T-TRN-020: 0.036 us/message framing+mediation on this host (not the G-M0 gate)."
  - id: M0-T06
    status: DONE
    tier: PC
    commit: fa36947
    tests_green: [T-E2E-001, T-E2E-002, T-E2E-003, T-E2E-006]
    notes: "mcp-gate binary: config (policy path, span log, shadow/enforce, message cap, dev signing seed), stdio proxy with --upstream CMD, per-tools/call evaluation via PolicyEngine(FsResolver), signed+chained fsync'd span per evaluated call, --report writes the would-have-blocked JSON. Shadow forwards and records; --enforce blocks non-Allow. Two real deadlock bugs found by the CLI test and fixed (upstream EOF ownership; per-write LockedWriter instead of holding the stdout mutex across a blocking read). Latency measured on this host: p50 4.0 / p95 5.4 / p99 8.0 ms including the fsync'd span commit; the probe is report-only on CI because P-LAT-1 must be measured on the ISSUE-001 storage profile. Dev signing seed is config-supplied (production must use the KeyStore) and G-M0 stays open pending ISSUE-001 plus the INV-1/chaos matrix."
  - id: M1-T01
    status: DONE
    tier: PC
    commit: 31fb39e
    tests_green: [T-POL-001, T-POL-002, T-POL-003, T-POL-004, T-POL-005, T-POL-006, T-POL-007, T-POL-008, T-POL-009, T-POL-010, T-POL-011, T-POL-012, T-POL-013, T-POL-014, T-POL-015, T-POL-016, T-POL-017, T-POL-018, T-POL-019, T-POL-020]
    notes: "Strict TOML parser: unknown keys, missing class/pin, invalid regex, unbounded limits, non-closed fail_mode and default_deny=false are all rejected. Pin = sha256:<64 lowercase hex>. Policy hash = sha256(JCS(parsed policy)), order-insensitive. PolicyEngine::decide does pin + strict allowlist (deny, never strip); value validators land in M1-T02. Pulled ahead of M0-T06 (DEC-005)."
  - id: M1-T02
    status: DONE
    tier: PC
    commit: da4176b
    tests_green: [T-PAR-001, T-PAR-002, T-PAR-003, T-PAR-004, T-PAR-005, T-PAR-006, T-PAR-007, T-PAR-008, T-PAR-009, T-PAR-010, T-PAR-011, T-PAR-012, T-PAR-013, T-PAR-014, T-PAR-015, T-PAR-016, T-PAR-017, T-PAR-018, T-PAR-019, T-PAR-020, T-PAR-021, T-PAR-022, T-PAR-023, T-PAR-024, T-PAR-025, T-PAR-026, T-PAR-027, T-PAR-028, T-PAR-029, T-PAR-030]
    notes: "Strict allowlist (deny, never strip), regex (linear, ReDoS corpus <10 ms), enum, inclusive numeric range, segment-aware path prefix with confusable/control rejection, injected PathResolver (LexicalResolver for pure tests, FsResolver canonicalises symlinks and new files through the parent), ASCII-only URL host allowlist (no userinfo, rejects IDN homographs, rejects nested redirect URLs), max_len/max_items exact boundaries, null-vs-absent and all type-confusion cases deny. PolicyEngine now REQUIRES a resolver (no insecure default); mcp-gate must inject FsResolver."
  - id: M1-T03
    status: DONE
    tier: PC
    commit: 88ccad8
    tests_green: [T-SCH-001, T-SCH-002, T-SCH-003, T-SCH-004, T-SCH-005, T-SCH-006, T-SCH-007, T-SCH-008, T-SCH-009, T-SCH-010, T-SCH-011, T-SCH-012, T-SCH-013, T-SCH-014, T-SCH-015, T-SCH-016, T-SCH-017, T-SCH-018]
    notes: "pin = H(JCS(descriptor)) over server+name+description+inputSchema+annotations+version; key-order churn keeps the pin, a single-byte or unicode-confusable edit changes it. Drift quarantines the tool (never auto-adopts); tools/list_changed cannot widen; quarantine is STICKY (checked before pin equality) so reverting to the pinned bytes reports QuarantineHeld, not Unchanged. Un-quarantine requires an out-of-band principal entry with its own audit event; an empty principal is rejected. invoke_allowed denies unknown/quarantined/policy-pin-mismatch with DENY_UNPINNED or DENY_DRIFT. Cross-server name collisions are namespaced as server:tool (full isolation/metadata handling is M1-T04)."
  - id: M1-T04
    status: DONE
    tier: PC
    commit: 1803871
    tests_green: [T-META-001, T-META-002, T-META-003, T-META-004, T-META-005, T-META-006, T-META-007, T-META-008, T-META-009, T-META-010, T-META-011, T-META-012, T-META-013, T-META-014, T-META-015, T-META-016]
    notes: "Delimit mode (default) frames descriptor text with an EXTERNAL_UNTRUSTED_DATA marker pair and escapes any forgery attempt, so the text can never break out; strip mode removes instruction clauses. Invisible characters (zero-width, unicode tags U+E0000-E007F, soft hyphen) are counted and removed in BOTH modes; base64-shaped tokens, cross-server server:tool references, instruction patterns, control chars and bidi overrides are recorded as FINDINGS ONLY (never a verdict, never a policy edit — T-META-005/006). Output is bounded with an explicit TRUNCATED_METADATA finding. Namespace registers server:tool, keeps both tools when names collide and logs the collision. Findings map to the closed METADATA_POISONING_SUSPECTED code at the wiring layer."
  - id: M2-T01
    status: DONE
    tier: PC
    commit: 486aac3
    tests_green: [T-PRV-001, T-PRV-002, T-PRV-003, T-PRV-004, T-PRV-005, T-PRV-006, T-PRV-007, T-PRV-008, T-PRV-009, T-PRV-010, T-PRV-011, T-PRV-012, T-PRV-013, T-PRV-014, T-PRV-015]
    notes: "Label lattice via gate-core::meet; append-only DAG (unknown parent rejected, cycles impossible); content-addressed ids (parent-order independent, idempotent); per-turn windows; hash-identified endorsed corpora with tamper demotion to EXTERNAL_UNTRUSTED_DATA; over-claiming a label is ProvenanceError::TaintRaised. Kani harness formal/lattice_monotone.rs still TODO (M6-T01)."
  - id: M2-T02
    status: DONE
    tier: PC
    commit: 19ca93c
    tests_green: [T-TNT-001, T-TNT-002, T-TNT-003, T-TNT-004, T-TNT-005, T-TNT-006, T-TNT-007, T-TNT-008, T-TNT-009, T-TNT-010, T-TNT-011, T-TNT-012, T-TNT-013, T-TNT-014, T-TNT-015, T-TNT-016, T-TNT-017, T-TNT-018, T-TNT-019, T-TNT-020]
    notes: "Structural taint: any untrusted segment in a turn window taints every output of that turn. TaintScorer may only add taint (ancestry meet dominates). Laundering corpus in gate-testkit: 200+ transforms (summarise 1..40, truncate 1..40, 5 case x 8 wrappers, 40 synonym swaps, 40 homoglyph/zero-width insertions, 40 encodings/chunkings); every transform that claims clean provenance is rejected with TaintRaised and honest derivation stays EXTERNAL_UNTRUSTED_DATA. 0 launders."
  - id: M2-T03
    status: DONE
    tier: PC
    commit: 19ca93c
    tests_green: [T-CTL-001, T-CTL-002, T-CTL-003, T-CTL-004, T-CTL-005, T-CTL-006, T-CTL-007, T-CTL-008, T-CTL-009, T-CTL-010, T-CTL-011, T-CTL-012]
    notes: "Control-flow taint: untrusted segment in the preceding window taints the call unless screened by a principal-only checkpoint. TaintPath explains from the least-trusted root (ticket #8841, line 14), bounded to 3 hops / 280 chars with an explicit omitted-hop count, stable sha256 digest."
  - id: M2-T04
    status: DONE
    tier: PC
    commit: b701b6c
    tests_green: [T-PIV-001, T-PIV-002, T-PIV-003, T-PIV-004, T-PIV-005, T-PIV-006, T-PIV-007, T-PIV-008, T-PIV-009, T-PIV-010, T-PIV-011, T-PIV-012, T-PIV-013, T-PIV-014]
    notes: "PolicyEngine::decide now halts tainted privileged calls: PivotMode::Deny (default, pre-M3) returns DENY_TAINT_PIVOT, PivotMode::Escalate returns ESCALATE_ENDORSEMENT_REQUIRED. READ_ONLY exempt; STATUS: IRREVERSIBLE clean allowed; PRIVILEGE_GRANTING untrusted escalates and blanket_allow is unrepresentable. CallRequest::with_taint merges the path hops into the AuthClosure. Model text never enters the decision (T-PIV-011). M3-T01 flips the default to Escalate and enforces E_max."
  - id: M2-T05
    status: DONE
    tier: PC
    commit: ee2b6ca
    tests_green: [T-PER-001, T-PER-002, T-PER-003, T-PER-004, T-PER-005, T-PER-006, T-PER-007, T-PER-008, T-PER-009, T-PER-010, T-PER-011, T-PER-012, T-PER-013, T-PER-014, T-PER-015, T-PER-016]
    notes: "PersistentStore (redb 2.6, copy-on-write ACID): write-through commit per insert, rollback to committed DB on failure, content-addressed ids survive reload via content_digest_hint, hash-identified endorsed corpora persist. Summarisation = meet (mixed content stays EXTERNAL). MemoryRecord stores label + full ancestry; recover_label is the meet with known ancestors (restart can never raise). VectorStore adapter preserves label through round-trip. kill -9 simulation (uncommitted txn absent after reopen), corrupt-file detection fails closed (size guard + catch_unwind around redb create), 8-thread concurrent writers behind Mutex = one store."
  - id: M2-T06
    status: DONE
    tier: PC
    commit: cace85e
    tests_green: [T-DEC-001, T-DEC-002, T-DEC-003, T-DEC-004, T-DEC-005, T-DEC-006, T-DEC-007, T-DEC-008]
    notes: "Scoped declassification: minting requires a DeclassifyAuthority trait; the agent channel holds DenyAllAuthority so model-initiated declassification is rejected (T-DEC-001). Records are scoped to one target; expired TTL restores the EXTERNAL taint (T-DEC-003); entries are stable-digest'd and serialisable for replay (T-DEC-004). The acceptance rule maps to GateError fail-closed: R12 applies (integration with M3 endorsement API pending)."
  - id: M3-T01
    status: DONE
    tier: PC
    commit: 3f842cf
    tests_green: [T-BUD-001, T-BUD-002, T-BUD-003, T-BUD-004, T-BUD-005, T-BUD-006, T-BUD-007, T-BUD-008, T-BUD-009, T-BUD-010, T-BUD-011]
    notes: "Per-episode, per-class E_max (default 5); hard cap, no in-band raise (request_band_raise logs InBandRaiseIgnored); out-of-band principal only via PrincipalGate, distinct CapChanged ledger event, Reset bounds used to the new cap; >=20s inter-prompt, DEC-P03 queue (renders only when due, budget consumed at render, overflow -> QueueFull + spam); similar-request cooldown clamps used. used<=cap holds after EVERY call (incl. render_due); seeded property test 1000 cases. LeafSink integration is M3-T04."
  - id: M3-T02
    status: DONE
    tier: PC
    commit: e0012ae
    tests_green: [T-BRF-001, T-BRF-002, T-BRF-003, T-BRF-004, T-BRF-005, T-BRF-006, T-BRF-007, T-BRF-008, T-BRF-009, T-BRF-010, T-BRF-011]
    notes: "Third-person briefs on deterministic (class, reversibility) templates; denial-list framing filter catches the >=150-string persuasion corpus; taint diff <=3 spans x <=280 chars with explicit marker; resolved effect concrete (destination, count, blast radius, no ellipses); agent justification quarantined (labelled UNTRUSTED — AUTHORED BY THE AGENT) and counted into w_sup; counter-considerations from the template set only; budget line k of E. Weights w_sup/w_cnt/w_neu computed; sup_share() defined (validated at M3-T03)."
  - id: M3-T03
    status: DONE
    tier: PC
    commit: 12ec25b
    tests_green: [T-SYM-001, T-SYM-002, T-SYM-003, T-SYM-004, T-SYM-005, T-SYM-006, T-SYM-007, T-SYM-008, T-SYM-009, T-SYM-010, T-SYM-011, T-SYM-012, T-SYM-013, T-SYM-014, T-SYM-015, T-SYM-016, T-SYM-017, T-SYM-018]
    notes: "Sup share = w_sup/(w_sup+w_cnt+w_neu) measured in rendered tokens AND rendered pixel area; the rule takes the max (P3-R7). >0.50 => not rendered + DENY_SYMMETRY (INV-6). Whitespace and zero-size blocks contribute nothing to the pixel measure; tiny-font counter text is pixel-weighted; collapsed justification is still counted; 200% zoom is ratio-invariant; screen-reader/render order is a fixed contract. Deterministic layout model (no browser in the loop); headless-browser cross-check (<=2% per block) is CI work for M3-T05 wiring, recorded as ISSUE-003."
  - id: M3-T04
    status: DONE
    tier: PC
    commit: a06fe53
    tests_green: [T-LDG-001, T-LDG-002, T-LDG-003, T-LDG-004, T-LDG-005, T-LDG-006, T-LDG-007, T-LDG-008, T-LDG-009, T-LDG-010, T-LDG-011, T-LDG-012, T-LDG-013, T-LDG-014, T-LDG-015, T-LDG-016, T-LDG-017, T-LDG-018, T-LDG-019, T-LDG-020, T-LDG-021, T-LDG-022, T-LDG-023, T-LDG-024, T-LDG-025, T-LDG-026]
    notes: "Leaf A carries every P3-R17 field (schema test), signed over JCS bytes with digest+signature verified; release requires H(JCS(outbound)) == call_digest (INV-5: one-byte mutation, wrong call, replay all denied); 15-min endorsement timeout fails closed; resume plan never re-prompts (Endorsed->Release, Released->ExecuteOnce, Executed->Done, NF-R5); Leaf B bound by ref=H(leaf_a) with 0..3 regret and duplicate-attestation rejection; tick() records AttestLapsed after delta_t and never invents confirmation (INV-8); delta_t bounds 1h..30d; asymmetric briefs are never endorsed; leaves exit ONLY through gate_core::LeafSink, implemented by VecSink and by gate_span::SpanLeafSink (signed, chained, fsync'd span chain, T-LDG-016b)."
  - id: M3-T05
    status: BLOCKED
    tier: DF(scope: WebAuthn dropped, Ed25519 device key)
    commit: null
    tests_green: []
    notes: ""
  - id: M3-T06
    status: DONE
    tier: PC
    commit: e7e04a2
    tests_green: [T-DRF-001, T-DRF-002, T-DRF-003, T-DRF-004, T-DRF-005, T-DRF-006, T-DRF-007, T-DRF-008, T-DRF-009, T-DRF-010, T-DRF-011, T-DRF-012, T-DRF-013, T-DRF-014]
    notes: "Per-principal trailing windows (20): rubber-stamp rate (<2 s), regret rate (Leaf B scale >=2; un-attested never counts), bounded sycophantic-drift score monotone in the stamp rate, per-principal isolation. auto_tighten fires only on a FULL window with regret >15%: lowers the cap by one (never raises, floor 1) and requires dual principal. Dual-principal brief is built from shared material only, so P1's decision/note are structurally absent; any split denies (DUAL_PRINCIPAL_SPLIT finding). Deterministic/replayable. G-M3 still unrun (ISSUE-004)."
  - id: M4-T01
    status: DONE
    tier: PC
    commit: 359d510
    tests_green: [T-MRK-001, T-MRK-002, T-MRK-003, T-MRK-004, T-MRK-005, T-MRK-006, T-MRK-007, T-MRK-008, T-MRK-009, T-MRK-010, T-MRK-011, T-MRK-012, T-MRK-013, T-MRK-014, T-MRK-015, T-MRK-016, T-MRK-017, T-MRK-018, T-MRK-019, T-MRK-020]
    notes: "RFC 9162 MTH with 0x00 leaf / 0x01 node domain separation, inclusion proofs and consistency proofs, redb TreeStore (append + reopen + corrupt-file fail-closed). Tree heads, inclusion proofs and consistency proofs are byte-identical to the independent ref/merkle_ref.py over 64 leaves / all (m,n) pairs up to n=24. NOTE: the verifying algorithm for consistency proofs is deliberately NOT shipped here — the first implementation failed its own round-trip and shipping it would be a false guarantee; proof-level agreement with the independent reference is what M4-T01 claims. Sound verify_consistency is M4-T04 (ISSUE-006)."
  - id: M4-T02
    status: DONE
    tier: PC
    commit: 88ffa64
    tests_green: [T-SLT-001, T-SLT-002, T-SLT-003, T-SLT-004, T-SLT-005, T-SLT-006, T-SLT-007, T-SLT-008, T-SLT-009, T-SLT-010, T-SLT-011, T-SLT-012, T-SLT-013, T-SLT-014, T-SLT-015, T-SLT-016, T-SLT-017, T-SLT-018]
    notes: "E = SHA256(salt || payload); Merkle leaf = H(0x00 || E). XChaCha20-Poly1305 evidence store with AAD binding to the leaf id, 32-byte salts from the injected Rng, payload bucketing/padding (256..64KiB, 4-byte length prefix) so ciphertext length does not leak. Selective disclosure reveals one salt+payload and recomputes exactly that leaf; shredding drops salt+ciphertext (idempotent) and every other inclusion proof still verifies. Key rotation re-encrypts all records. 'Grep the log' test scans persisted bytes and finds no plaintext, no unsalted digest, no entry digest and no salt. Salts are never persisted with the log."
  - id: M4-T03
    status: TODO
    tier: PC
    commit: null
    tests_green: []
    notes: ""
  - id: M4-T04
    status: TODO
    tier: PC
    commit: null
    tests_green: []
    notes: ""
  - id: M5-T01
    status: DONE
    tier: PC
    commit: cebddf2
    tests_green: [T-VBN-001, T-VBN-002, T-VBN-003, T-VBN-004, T-VBN-005, T-VBN-006, T-VBN-007, T-VBN-008, T-VBN-009, T-VBN-010, T-VBN-011, T-VBN-013, T-VBN-014, T-VBN-015, T-VBN-017, T-VBN-018, T-VBN-019, T-VBN-020, T-SCN-001, T-SCN-002, T-SCN-003]
    notes: "Hermetic deterministic runner (no clock/net/tokio — asserted by a source-level test), scenario schema+loader with duplicate-id and family validation, coverage matrix, TargetFramework adapter (ungated reference + deny-all ablations + external adapters), oracle profiles (diligent/distracted/fatigued) seeded per scenario with persuasion bias, JCS-signed manifest (bench_version, git_sha, policy_hash, agent_ids, seeds, scenario_set_hash, results_hash) with tamper/wrong-key rejection, order-independent scenario-set hash, results hash, and the NRP reporting rule (refuses without ASR/utility/E_bar). Scenarios are JSON (valid YAML 1.2) to avoid an unmaintained YAML dep (DEC-006). mcp-gate wiring is M0-T06/M5-T03; evals/public currently has 1 AF1 + 1 BEN scenario, so the ≥40-per-family requirement is M5-T02."
  - id: M5-T02
    status: DONE
    tier: PC
    commit: a69596c
    tests_green: [T-SCN-001, T-SCN-002, T-SCN-003, T-SCN-004, T-SCN-005, T-SCN-006]
    notes: "Deterministic generator (evals/generate_public.py) produces the committed corpus: 40 AF1 + 40 AF2 + 40 AF3 + 40 AF4 + 200 BEN = 360 scenarios, 8 subfamilies x 5 variants per attack family and 8 subfamilies x 25 per benign family, matching §6.4's coverage matrix shape. Tests assert per-family minimums, >=8 subfamilies and >=5 variants each, sorted ids, globally unique seeds, and that re-running the generator is byte-identical (so the corpus cannot silently drift). Scenario CONTENT is templated per subfamily: descriptions are placeholders, not yet curated attack texts — curation is a human-review task and the eval numbers therefore remain provisional."
  - id: M5-T03
    status: IN_PROGRESS
    tier: PC
    commit: 62fd532
    tests_green: []
    notes: ""
  - id: M6-T01
    status: BLOCKED
    tier: DF(tool-missing: kani)
    commit: null
    tests_green: []
    notes: "Kani toolchain is not installed and §0.7 records that whether Kani can discharge the lattice/budget proofs at the stated size is unverified. Writing harnesses that cannot be run would be a false claim of formal verification."
  - id: M6-T02
    status: BLOCKED
    tier: DF(reduced: 8h campaign)
    commit: null
    tests_green: []
    notes: "Three fuzz targets exist (jcs_parse, mcp_frame, policy_toml) with committed corpora, but the acceptance criterion is >=72h cumulative runtime, which is wall-clock and cannot be satisfied in a coding session."
  - id: M6-T03
    status: BLOCKED
    tier: DF(low priority)
    commit: null
    tests_green: []
    notes: "Needs two independent builders producing identical hashes plus a CycloneDX SBOM and signed release. No release pipeline or SBOM tool is provisioned; the CI 'release' job in §7 does not exist yet."
  - id: M6-T04
    status: DONE
    tier: DF(scope)
    commit: fdf589d
    tests_green: [T-CRY-001, T-CRY-004, T-CRY-010]
    notes: "`--features fips` on gate-crypto disables Ed25519 at three points (SuiteId::parse, Ed25519Signer::sign, Ed25519Verifier::verify) returning GateError::Unsupported rather than silently falling back; ECDSA-P256 + SHA-256 continue to work end-to-end. The Ed25519 known-answer suite is cfg'd out under FIPS by design (tests/fips.rs covers the FIPS surface); CI runs both profiles."
  - id: M6-T05
    status: DONE
    commit: fdf589d
    tests_green: []
    notes: "docs/pentest-brief.md (scope per crate, out-of-scope incl. unimplemented M3-T05/M4-T03, rules of engagement, known false-confidence traps) and docs/known-gaps.md (all open issues, pending DEC items, unverified §0.7/§12 claims, and an explicit list of what the tests do NOT establish). No external engagement has been performed; P0/P1 closure is a human gate at GA."

notes_pilot: "PILOT-STATIC run committed: results/pilot.md + results/pilot.json. B0 100% ASR / 100% utility; B1 0% ASR / 62.5% utility / 37.5% FPR; B3 (pinning+allowlist, no provenance) 100% ASR; G (B3 + boundary taint) 0% ASR (ub 7.2%, n=40) / 100% utility / 0% FPR. Harness discriminates and the deny-all baseline is punished. The 0% is by construction (scenario declares taint), so this validates enforcement correctness, not real-world effectiveness. Pre-registration committed first (evals/PREREG.md); Clopper-Pearson bounds unit-tested."

notes_research: "H6/H7 (added to evals/PREREG.md after the pilot, before running): cross-session laundering test in crates/gate-policy/tests/laundering.rs shows the provenance-derived closure denies a delayed privileged call with allowlisted params (DENY_TAINT_PIVOT, path names ticket #8841 line 14) while the policy-only configuration allows the identical call; restart cannot launder the label. H7 shows conservative turn-window taint denies a benign read->allowlisted-write flow and a principal-only checkpoint restores it (over-taint cost, measured as the frontier). void-bench now derives taint from a real ProvenanceStore per scenario instead of a scenario flag."

notes_s1_s4: "(a) H7 is now a SENSITIVITY CURVE, not a point estimate (results/frontier.md): the earlier '50% of ALL benign scenarios' came from hardcoding 4 of 8 benign subfamilies as reading untrusted content and inserting a synthetic read into each, so the 50% was the classification and the 100% denial was the pivot rule. The curve reports cost = f(assumed share of benign tasks that read untrusted data); a workload estimate needs traces, which this corpus does not contain. (b) Frozen split: 360 TEST-* scenarios, hashed, run once -> results/test.md; it reproduces the dev result, but the split differs only by ids, seeds and four phrasing templates (descriptions remain placeholders), so this is reproducibility, not generalisation. (c) Real-model runs, the paired gate evaluation and a fixed-budget adaptive attacker are DONE (H8b/H8c/H8d; three digest-pinned local models; 78/78 successful attack calls denied by G and allowed by B3). NOT done: AgentDojo/MCPTox adapter (no network fetch; the Adaption corpus could not be exported — ISSUE-010), frontier models, neutral summarizer, CaMeL/FIDES comparison, an mcp-gate end-to-end run with instrumented provenance."
notes_real_model: "H8 (2026-11, EXPLORATORY) is superseded by H8b (pre-registered at 71aa4e1, run once, 13m46s). Three digest-pinned local models (llama3.2 a80c4f17, gemma3:4b 68ceab7e, qwen3:4b 359d7dd4), 24 rows/model (15 attack / 9 benign), paired B3/G on identical transcripts. Plain ASR 36/45 = 80.0% (67.7-89.1); b2 27/45 = 60.0%; b2allow 15/45 = 33.3%; benign utility 81/81 = 100% (96.4-100). On the 78 successful attack calls: B3 allows 78/78, G denies 78/78 (0/78 allows, ub 3.8%), every denial DENY_TAINT_PIVOT. H8b-1 supported. H8b-2 partially supported and FALSIFIED for gemma3: b2allow is 0/15 there, i.e. it does reach the gate's rate. Prompt hardening is model-dependent: b2 was 15/15 ASR on gemma3 and 3/15 on llama3.2. Limits: 3-4B models, assisted summarizer, memory passed as text, harness-assigned provenance label, no mcp-gate in the loop, b2allow is handed the permitted recipient. The old H8 classifier (truncation at the first dot, any @ counted, including refusals) and its 0/10 utility reading are corrected in the result file. results/model_pilot.md + results/model_pilot.jsonl (216 records). H8c/H8d (adaptive, self-play, budget 3): plain 5/5 by budget 2, b2allow 3/5 at budget 1; G allows 0/10 successful calls, B3 allows 7/7 (see results/model_adaptive.md)."
notes_external: "H9 (InjecAgent-derived, MIT, arXiv:2403.02691): 6 attack / 6 benign rows per model, llama3.2 + gemma3 (qwen3 excluded after 180s/call on long prompts). Plain 6/12 = 50.0% (24.5-75.5), b2allow 4/12 = 33.3% (12.3-60.9); on the 10 successful calls B3 allows 10/10 and G denies 10/10. llama3.2 falls from 80% on hand-written tickets to 17% on external prose, which is why H9 matters (and it cuts against the earlier headline). Utility 4-5/6: failures are wrong addresses found in the tool output, not refusals. H10 (neutral summariser): plain 11/15 = 73.3% vs 80.0% assisted; effect is model-specific (llama 80->40, gemma 100->100, qwen 60->80), so the assisted prompt is not a general inflator. H11 (policy-aware attacker): 3/5 at budget 1, same as H8d; hypothesis not supported; the attacker model often refuses to rewrite. model_transcript.rs persists a real gemma3 summary through redb reopen and still denies DENY_TAINT_PIVOT. ISSUE-010 (Adaption export) remains open."
notes_h12: "Hosted frontier-scale replication via Adaption's OpenAI-compatible API (qwen3.8-27b 24 rows, deepseek-v4-flash 23 rows, gemma-4-31b-it 24 rows; qwen3.5-397b dropped at 5/24 in 30 min, ~90s/call). Plain ASR 32/45 = 71.1% (58.0-82.0); on the 32 successful calls B3 allows 32/32 and G denies 32/32 (DENY_TAINT_PIVOT). b2 (no permitted address) is 0/45 ASR but utility 3/26 = 11.5% — safe by breaking the task. b2allow (recipient out-of-band) is 0/45 ASR with utility 21/26 = 80.8%. H12 is therefore PARTIALLY FALSIFIED: on these models a utility-preserving prompt defence eliminated the attack, so the gate's marginal value is not shown in that arm; the gate's value is enforcement when the recipient cannot be stated out-of-band or the model ignores the prompt (local 3B models, gemma4). glm-5.2 refused at the provider layer (security policy). No content digest from the API; model id is the pin. results/model_pilot_frontier.md + .jsonl."
notes_h13_h14: "H13 (cost of G): 9 benign external-content templates x 3 reps x 3 hosted models. Raw utility 49/81 = 60.5% (49.4-70.8); under G 0/81 (0.0-3.6). The conservative rule denies every legitimate external-content flow the model completes; the principal checkpoint (H7) is the recovery mechanism. H14 (external, attack-only): 100 InjecAgent-derived attack cases on gemma-4-31b-it; plain 44/100 = 44.0% (35.6-52.7), b2allow 0/100 (0.0-3.0); G denies 44/44 successful calls, B3 allows them. Transport provenance: mcp-gate now labels tools/call responses itself and denies the next call (crates/mcp-gate/tests/transport_taint.rs, 5 tests); trust_tool_results is the coarse principal override. Citation metadata for InjecAgent/AgentPoison/MINJA/AgentDojo verified against arxiv.org on 2026-11-16."
notes_h15: "Live end-to-end through the real mcp-gate process: gemma-4-31b-it via the hosted API, fake upstream, enforce. Attacker ticket: 7/7 chose attacker, 7/7 blocked with JSON-RPC -32001; shadow control: 3/3 executed; benign ticket: 3/3 chose partner, 3/3 blocked (the cost, matching H13). To make this work, gate-transport now sends FrameKind::Response through the mediator (it previously short-circuited), and mcp-gate labels the matching tools/call response itself (EXTERNAL default, PRINCIPAL with trust_tool_results or per-tool trusted_tools). Run stopped at a provider 429 (7 enforce, not 10); retries/backoff are implemented. results/e2e_gate.md + .jsonl."
notes_h16: "Validation-breadth pass: (a) full model corpus through the real mcp-gate CLI (8 rows x 3 modes local llama3.2; 4 attack rows x 2 modes hosted gemma-4). Every attack call blocked; benign executed 0/3 (cost). (b) Real AgentDojo v1.2 baseline: workspace deepseek 20x3 utility 55/60, security 0/60; workspace gemma/qwen 10x2 utility 20/20, security 0/20; travel qwen direct 8x2 utility 16/16, security 1/16. Post-hoc boundary replay prevents 1/1 successful travel attack; utility upper-bound loss 10/16. Native AgentDojo defense + CaMeL/FIDES comparison remain open. (c) Per-segment checkpoint at the transport: principal_approved content digests; approved segment declassified, different segment from the same tool not (transport_taint.rs). All three runs are EXPLORATORY (not pre-registered)."
notes_h17: "Validation closure: (a) H17 larger-n replication, 2 local models x 6 reps (30 attack rows each): plain 54/60 = 90.0% (81.2-95.6), b2 36/60 = 60.0% (48.6-70.7), b2allow 18/60 = 30.0% (20.4-41.2); utility 108/108; G denies 108/108, B3 allows 108/108. Confirms H8b (llama b2 20% both, b2allow 60% both; gemma3 b2 100% both). (b) Native AgentDojo defense (evals/agentdojo_defense.py, ProvenanceGateLoop): travel qwen direct 8x2 utility 6/16 = 37.5%, security 0/16 (baseline 16/16, 1/16); the block stops the loop, so no context fail-safe. (c) 360-scenario corpus through the CLI (evals/cli_bench.py): public and test, G blocks 160/160 attacks (44.4% of 360), B3 0/360, all 200 benign allowed. Scripted/templated, not a model. Remaining: CaMeL/FIDES comparison, Rust gate linked into AgentDojo, model-driven 360, human checkpoint study."
issues:
  - id: ISSUE-009
    task: all (scope)
    kind: SPEC_CONFLICT
    detail: "RESOLVED in substance: NOVA-EL-L5-RESEARCH-TRACK.md has been in the repo since 62fd532, so the authoritative remaining-scope list is readable. The overlay declares itself active (plan.md banner), but S0 adoption is still incomplete: STATE has not been retagged PC/EN/DF, current_phase still says M0, and the S-step mapping does not appear. Close this issue when S0 lands; do not claim the research track is adopted until then."
    status: RESOLVED
  - id: ISSUE-010
    task: external validity
    kind: TOOL_BLOCKED
    detail: "Adaption MCP dataset generation succeeded (ce355f56-3168-48dd-a793-42e5ac739800, 120 rows, technology/cybersecurity), but the MCP exposes no row export: get_dataset_export_links returns null for all three targets and there is no fetch-rows tool. The corpus therefore cannot be ingested this session. results/adaption.md records the converter and the three unblock steps. No external-benchmark claim is made. AgentDojo/MCPTox remain unrun."
    status: OPEN
  - id: ISSUE-008
    task: M6-T01/M6-T02/M6-T03
    kind: DEP_BLOCKED
    detail: "Kani toolchain (M6-T01), 72h wall-clock fuzzing (M6-T02) and a reproducible-build/SBOM release pipeline (M6-T03) are external resources, not code. Marked BLOCKED rather than DONE so STATE.md does not overstate hardening."
  - id: ISSUE-006
    task: M4-T01/M4-T03/M4-T04
    kind: NEEDS_HUMAN
    detail: "verify_consistency (RFC 9162 §2.1.4.2) is NOT shipped. Prover output is byte-identical to ref/merkle_ref.py, but a verifier is required before a witness may cosign (M4-T03) or mcp-audit may claim consistency checking (M4-T04). Diagnosis for whoever picks this up: the fr/sr fold in the RFC text is level- and left/right-sensitive, and my attempted transcription of the 'odd sn => sibling side' rule is wrong. Concrete counterexamples to test against (proofs produced by ref/merkle_ref.py): (m=2,n=8) proof=[H23,H47] old=H01; (m=6,n=8) proof=[H45,H67,L0147]; (m=7,n=8) proof=[l6,l7,H45,L]; (m=8,n=16) proof=[R815]. A correct rule must satisfy all four: m=2 needs p to be a right sibling at both levels while the *old* fold must stop at H01; m=8 needs H(old,p). Establishing the rule from the RFC text (rather than guessing) is the blocker; I will not ship a self-consistent guess (R10, §0.5)."
    status: OPEN
  - id: ISSUE-007
    task: M4-T03
    kind: NEEDS_HUMAN
    detail: "BLOCKED on DEC-P04 (own STH format + witness/cosignature protocol vs an existing community spec) AND on ISSUE-006 (a witness must verify consistency to its last-cosigned head before cosigning; without a sound verifier a cosignature is worthless). Per R12 the proposed behaviour can be implemented behind a config flag once the format is decided; it is not started rather than stubbed."
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
  - id: DEC-006
    summary: "M5-T01 (void-bench) implemented before M4-T04, and scenarios are JSON rather than YAML."
    rationale: "ISSUE-004 makes the eval harness the critical path: without it no phase gate can run. M5-T01's declared dep on M4-T04 is satisfied for the runner/adapter purposes by reference targets (UngatedTarget/deny-all/external adapter); mcp-gate wiring stays M0-T06. JSON is a YAML 1.2 subset, so scenario files remain YAML-readable without adding an unmaintained YAML crate to the tooling."
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
