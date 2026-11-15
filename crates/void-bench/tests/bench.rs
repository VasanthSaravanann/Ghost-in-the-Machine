//! T-VBN-001..020 + T-SCN-001..003 (plan.md §6, M5-T01).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gate_crypto::{Ed25519Signer, KeyId};
use gate_testkit::SeededRng;
use void_bench::{
    coverage, load_dir, results_hash, scenario_set_hash, AgentMode, BenchCall, CallOutcome,
    ManifestBody, Metrics, Oracle, OracleProfile, Run, Runner, Scenario, ScenarioError,
    ScenarioResult, SignedManifest, TargetFramework, UngatedTarget,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn scenario(id: &str, family: &str) -> Scenario {
    Scenario {
        id: id.into(),
        family: family.into(),
        subfamily: "test".into(),
        seed: 7,
        description: "d".into(),
        agent: AgentMode::Gullible,
        oracle: OracleProfile::Diligent,
        attacker_goals: if family == "BEN" {
            vec![]
        } else {
            vec!["effect".into()]
        },
        benign_expected: vec![],
        tags: vec![],
    }
}

fn evaluate(s: &Scenario, target: &mut dyn TargetFramework, _o: &Oracle) -> ScenarioResult {
    let call = BenchCall {
        scenario: "s".into(),
        tool: "mailer:send_email".into(),
        intent: "intent".into(),
        tainted: true,
        approved: true,
    };
    let outcome = target.call(&call);
    let benign = s.family == "BEN";
    ScenarioResult {
        scenario: s.id.clone(),
        family: s.family.clone(),
        attacker_effects: usize::from(outcome.executed && !benign),
        benign_completed: outcome.executed && benign,
        escalations: 0,
        calls: 1,
        blocked: u32::from(!outcome.executed),
        trace: vec!["t".into()],
    }
}

fn run_with(target: &mut dyn TargetFramework, scenarios: &[Scenario]) -> Run {
    Runner::default().run(
        scenarios,
        target,
        |seed| Box::new(SeededRng::new(seed)),
        &mut evaluate,
    )
}

// T-VBN-001/002 — determinism and seed sensitivity.
#[test]
fn t_vbn_001_002_runs_are_bit_identical_and_seeded() {
    let scenarios = vec![scenario("AF1-001", "AF1"), scenario("BEN-001", "BEN")];
    let mut a_target = UngatedTarget;
    let mut b_target = UngatedTarget;
    let a = run_with(&mut a_target, &scenarios);
    let b = run_with(&mut b_target, &scenarios);
    assert_eq!(a, b);
    assert_eq!(results_hash(&a), results_hash(&b));
    let mut other = scenarios.clone();
    other[0].seed = 8;
    let mut c_target = UngatedTarget;
    let c = run_with(&mut c_target, &other);
    assert_ne!(a.seeds, c.seeds);
}

// T-VBN-003 — manifest signs/verifies, tampering fails.
#[test]
fn t_vbn_003_manifest_signature() {
    let scenarios = load_dir(root().join("evals/public")).unwrap();
    let body = ManifestBody {
        bench_version: "0.1.0".into(),
        git_sha: "deadbeef".into(),
        policy_hash: "sha256:policy".into(),
        agent_ids: vec!["gullible".into()],
        seeds: scenarios.iter().map(|s| s.seed).collect(),
        scenario_set_hash: scenario_set_hash(&scenarios),
        results_hash: "sha256:results".into(),
    };
    let signer = Ed25519Signer::from_seed(KeyId::new("bench"), &[4u8; 32]);
    let signed = SignedManifest::sign(body, &signer).unwrap();
    assert!(signed.verify(&signer.verifying_key()).is_ok());
    let mut tampered = signed.clone();
    tampered.body.results_hash = "sha256:other".into();
    assert!(tampered.verify(&signer.verifying_key()).is_err());
    let other = Ed25519Signer::from_seed(KeyId::new("bench"), &[5u8; 32]);
    assert!(signed.verify(&other.verifying_key()).is_err());
}

// T-VBN-004 — scenario-set hash is order independent.
#[test]
fn t_vbn_004_scenario_set_hash_order_independent() {
    let mut scenarios = load_dir(root().join("evals/public")).unwrap();
    let a = scenario_set_hash(&scenarios);
    scenarios.reverse();
    assert_eq!(a, scenario_set_hash(&scenarios));
    scenarios[0].seed += 1;
    assert_ne!(a, scenario_set_hash(&scenarios));
}

// T-SCN-001..003 — schema and loader.
#[test]
fn t_scn_001_schema_validation() {
    assert!(scenario("AF1-001", "AF1").validate().is_ok());
    let mut no_goal = scenario("AF1-002", "AF1");
    no_goal.attacker_goals.clear();
    assert!(no_goal.validate().is_err());
    let mut bad_family = scenario("X", "AF9");
    bad_family.family = "AF9".into();
    assert_eq!(
        bad_family.validate().unwrap_err(),
        ScenarioError::UnknownFamily("AF9".into())
    );
    let mut empty = scenario("BEN-1", "BEN");
    empty.id.clear();
    assert!(empty.validate().is_err());
}

#[test]
fn t_scn_002_duplicate_ids_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::to_string_pretty(&scenario("AF1-001", "AF1")).unwrap();
    std::fs::write(dir.path().join("a.json"), &body).unwrap();
    std::fs::write(dir.path().join("b.json"), &body).unwrap();
    assert_eq!(
        load_dir(dir.path()).unwrap_err(),
        ScenarioError::DuplicateId("AF1-001".into())
    );
}

#[test]
fn t_scn_003_loader_sorted_and_coverage() {
    let scenarios = load_dir(root().join("evals/public")).unwrap();
    let ids: Vec<&str> = scenarios.iter().map(|s| s.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    let matrix = coverage(&scenarios);
    assert_eq!(matrix.len(), 5);
    assert_eq!(matrix.get("AF1"), Some(&1));
    assert_eq!(matrix.get("BEN"), Some(&1));
    assert_eq!(matrix.get("AF3"), Some(&0));
}

// T-VBN-005/006 — metrics and the NRP reporting rule.
#[test]
fn t_vbn_005_metrics_and_nrp() {
    let mk =
        |family: &str, atk: usize, ben: bool, esc: u32, calls: u32, blocked: u32| ScenarioResult {
            scenario: "s".into(),
            family: family.into(),
            attacker_effects: atk,
            benign_completed: ben,
            escalations: esc,
            calls,
            blocked,
            trace: vec![],
        };
    let run = Run {
        seeds: vec![1],
        results: vec![
            mk("AF1", 1, false, 0, 1, 0),
            mk("AF1", 0, false, 0, 1, 1),
            mk("BEN", 0, true, 2, 4, 1),
        ],
    };
    let m = Metrics::compute(&run);
    assert_eq!(m.asr.get("AF1"), Some(&0.5));
    assert_eq!(m.retained_utility, 1.0);
    assert_eq!(m.e_bar, 2.0);
    assert!((m.fpr - 0.25).abs() < 1e-9);
    assert!(m.nrp().unwrap().is_finite());
}

#[test]
fn t_vbn_006_nrp_refused_without_components() {
    let empty = Metrics {
        asr: BTreeMap::new(),
        retained_utility: 1.0,
        e_bar: 0.0,
        fpr: 0.0,
    };
    assert!(empty.nrp().is_err());
    let no_utility = Metrics {
        asr: [("AF1".to_string(), 0.0)].into_iter().collect(),
        retained_utility: f64::NAN,
        e_bar: 0.0,
        fpr: 0.0,
    };
    assert!(no_utility.nrp().is_err());
}

// T-VBN-007/008 — metric sanity: deny-all and ungated bounds.
#[test]
fn t_vbn_007_deny_all_scores_poorly() {
    struct DenyAll;
    impl TargetFramework for DenyAll {
        fn call(&mut self, _: &BenchCall) -> CallOutcome {
            CallOutcome {
                executed: false,
                effect: None,
                blocked_reason: Some("denied".into()),
            }
        }
    }
    let scenarios = vec![scenario("AF1-001", "AF1"), scenario("BEN-001", "BEN")];
    let mut target = DenyAll;
    let run = run_with(&mut target, &scenarios);
    let m = Metrics::compute(&run);
    assert_eq!(m.asr.get("AF1"), Some(&0.0));
    assert_eq!(m.retained_utility, 0.0);
    assert!(m.nrp().unwrap() < 0.5);
}

#[test]
fn t_vbn_008_ungated_is_upper_bound() {
    let scenarios = vec![scenario("AF1-001", "AF1"), scenario("AF1-002", "AF1")];
    let mut target = UngatedTarget;
    let run = run_with(&mut target, &scenarios);
    assert_eq!(Metrics::compute(&run).asr.get("AF1"), Some(&1.0));
}

// T-VBN-009..011 — oracle profiles.
#[test]
fn t_vbn_009_oracle_deterministic() {
    let a = Oracle::new(OracleProfile::Distracted, Box::new(SeededRng::new(11)));
    let b = Oracle::new(OracleProfile::Distracted, Box::new(SeededRng::new(11)));
    for _ in 0..8 {
        assert_eq!(a.decide(0), b.decide(0));
    }
}

#[test]
fn t_vbn_010_oracle_profiles_differ() {
    let diligent = Oracle::new(OracleProfile::Diligent, Box::new(SeededRng::new(3)));
    let fatigued = Oracle::new(OracleProfile::Fatigued, Box::new(SeededRng::new(3)));
    let d = diligent.decide(0);
    let f = fatigued.decide(0);
    assert_eq!(d.read_fraction, 100);
    assert!(f.latency_ms < d.latency_ms);
    assert!(f.read_fraction < d.read_fraction);
}

#[test]
fn t_vbn_011_persuasion_biases_distracted() {
    let low = Oracle::new(OracleProfile::Distracted, Box::new(SeededRng::new(5)));
    let high = Oracle::new(OracleProfile::Distracted, Box::new(SeededRng::new(5)));
    let low_yes = (0..200).filter(|_| low.decide(0).endorses).count();
    let high_yes = (0..200).filter(|_| high.decide(40).endorses).count();
    assert!(high_yes > low_yes, "{low_yes} vs {high_yes}");
}

// T-VBN-013..016 — adapters, hermeticity, traces, coverage.
#[test]
fn t_vbn_013_adapter_accepts_other_frameworks() {
    struct Echo;
    impl TargetFramework for Echo {
        fn call(&mut self, call: &BenchCall) -> CallOutcome {
            CallOutcome {
                executed: call.approved,
                effect: None,
                blocked_reason: None,
            }
        }
    }
    let scenarios = vec![scenario("AF1-001", "AF1")];
    let mut echo = Echo;
    let run = run_with(&mut echo, &scenarios);
    assert_eq!(run.results.len(), 1);
}

#[test]
fn t_vbn_014_runner_is_hermetic() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    for forbidden in ["std::net", "SystemTime", "Instant::now", "tokio"] {
        assert!(
            !source.contains(forbidden),
            "void-bench must stay hermetic: {forbidden}"
        );
    }
}

#[test]
fn t_vbn_015_trace_and_coverage() {
    let scenarios = vec![scenario("AF1-001", "AF1")];
    let run = run_with(&mut UngatedTarget, &scenarios);
    assert_eq!(run.results[0].trace, vec!["t".to_string()]);
    assert_eq!(coverage(&[]).len(), 5);
    assert!(coverage(&[]).values().all(|v| *v == 0));
}

// T-VBN-017..020 — manifest fields, results hash, randomness, public corpus.
#[test]
fn t_vbn_017_manifest_fields_present() {
    let scenarios = load_dir(root().join("evals/public")).unwrap();
    let body = ManifestBody {
        bench_version: "0.1.0".into(),
        git_sha: "abc".into(),
        policy_hash: "sha256:p".into(),
        agent_ids: vec!["gullible".into()],
        seeds: vec![1],
        scenario_set_hash: scenario_set_hash(&scenarios),
        results_hash: results_hash(&Run::default()),
    };
    let json = serde_json::to_value(&body).unwrap();
    for field in [
        "bench_version",
        "git_sha",
        "policy_hash",
        "agent_ids",
        "seeds",
        "scenario_set_hash",
        "results_hash",
    ] {
        assert!(json.get(field).is_some(), "missing {field}");
    }
}

#[test]
fn t_vbn_018_results_hash_tracks_results() {
    let mut run = Run::default();
    let h = results_hash(&run);
    run.seeds.push(1);
    assert_ne!(h, results_hash(&run));
}

#[test]
fn t_vbn_019_seeded_rng_only() {
    let make = |seed: u64| {
        let rng = SeededRng::new(seed);
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        buf
    };
    assert_eq!(make(42), make(42));
    assert_ne!(make(42), make(43));
}

#[test]
fn t_vbn_020_public_scenarios_valid() {
    let scenarios = load_dir(root().join("evals/public")).unwrap();
    assert!(!scenarios.is_empty());
    for s in scenarios {
        s.validate().unwrap();
        assert!(s.seed > 0);
        assert!(!s.description.is_empty());
    }
}
