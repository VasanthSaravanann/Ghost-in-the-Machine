//! T-REPO-001..006 — repository and CI guardrails must actually be enforced.
//!
//! Each test executes the real check (never a mock of it): the checks are the
//! enforcement mechanism (plan.md §0.2 R9/R11, §0.6).

#![allow(clippy::print_stdout, clippy::print_stderr)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("crate lives at <repo>/crates/gate-testkit")
}

fn run(script: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(script)
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|e| panic!("failed to run {script}: {e}"));
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[test]
fn t_repo_001_ci_runs_required_checks() {
    let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    for needle in [
        "cargo fmt --check",
        "clippy",
        "-D warnings",
        "cargo test",
        "cargo deny check",
        "cargo audit",
        "tcb_lang_check.py",
    ] {
        assert!(
            ci.contains(needle),
            "CI is missing required check: {needle}"
        );
    }
}

#[test]
fn t_repo_002_product_crate_cannot_depend_on_testkit() {
    let (_ok, text) = run("python3", &["ci/scripts/dep_rule_check.py"]);
    assert!(text.contains("clean"), "clean tree must pass: {text}");
    let (ok, text) = run("python3", &["ci/scripts/dep_rule_check.py", "--self-test"]);
    assert!(ok, "seeded testkit dependency was not caught: {text}");
}

#[test]
fn t_repo_003_eval_path_grep_fails_build() {
    let (ok, text) = run("bash", &["ci/scripts/r_grep.sh"]);
    assert!(ok, "clean tree must pass r-grep: {text}");

    let dir = tempfile::tempdir().unwrap();
    let crates = dir.path().join("crates/gate-core/src");
    std::fs::create_dir_all(&crates).unwrap();
    std::fs::write(
        crates.join("lib.rs"),
        "pub fn cheat() { let _ = \"evals/public\"; }\n",
    )
    .unwrap();
    let (ok, text) = run(
        "bash",
        &["ci/scripts/r_grep.sh", dir.path().to_str().unwrap()],
    );
    assert!(!ok, "eval-path reference must fail the build: {text}");
}

#[test]
fn t_repo_004_decision_crates_forbid_unsafe() {
    let (ok, text) = run("bash", &["ci/scripts/forbid_unsafe_check.sh"]);
    assert!(ok, "forbid(unsafe_code) missing: {text}");
}

#[test]
fn t_repo_005_native_dep_in_decision_crate_fails() {
    let (ok, text) = run("python3", &["ci/scripts/tcb_lang_check.py"]);
    assert!(ok, "clean tree must pass tcb-lang-check: {text}");
    let (ok, text) = run("python3", &["ci/scripts/tcb_lang_check.py", "--self-test"]);
    assert!(ok, "seeded native dependency was not caught: {text}");
}

#[test]
fn t_repo_006_unwrap_outside_tests_fails_clippy() {
    let (ok, text) = run("python3", &["ci/scripts/lint_self_test.py"]);
    assert!(ok, "unwrap lint is not enforced: {text}");
}
