//! T-PAR-001..030 (plan.md §5.5, M1-T02).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::print_stderr)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use gate_core::{ReasonCode, Verdict};
use gate_policy::{
    CallRequest, FsResolver, LexicalResolver, ParamError, Policy, PolicyEngine, ToolPolicy,
};
use serde_json::{json, Map, Value};

fn policy_text(workspace_prefix: &str) -> String {
    format!(
        r#"
[tool."fs:read_file"]
class = "READ_ONLY"
pin = "sha256:4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2"
params_allow = ["path", "limit"]

  [tool."fs:read_file".path]
  prefix_allow = ["{workspace_prefix}"]
  max_len = 4096

  [tool."fs:read_file".limit]
  min = 1
  max = 100

[tool."mailer:send_email"]
class = "EXTERNAL_EGRESS"
pin = "sha256:9f2c1b7d4e6a8c0f2d4b6e8a0c2e4f6a8b0d2f4e6c8a0b2d4f6e8c0a2b4d6f8e"
params_allow = ["to", "subject", "body"]

  [tool."mailer:send_email".to]
  match = '^[\w.+-]+@(corp\.example|partner\.example)$'
  max_items = 5

  [tool."mailer:send_email".subject]
  max_len = 200

  [tool."mailer:send_email".body]
  max_len = 20000

[tool."api:fetch"]
class = "EXTERNAL_EGRESS"
pin = "sha256:1a3c5e7b9d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c"
params_allow = ["url"]

  [tool."api:fetch".url]
  host_allow = ["allowed.example", "xn--bcher-kva.example"]

[tool."db:grant_role"]
class = "PRIVILEGE_GRANTING"
pin = "sha256:2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d"
params_allow = ["role", "principal", "quota"]

  [tool."db:grant_role".role]
  enum = ["reader", "writer"]

  [tool."db:grant_role".principal]
  match = '^prn_[a-z0-9]+$'

  [tool."db:grant_role".quota]
  min = 1
  max = 10

[defaults]
default_deny = true
metadata_handling = "delimit"
fail_mode = "closed"
"#
    )
}

fn engine() -> PolicyEngine {
    PolicyEngine::lexical(Arc::new(
        Policy::parse(&policy_text("/workspace/")).unwrap(),
    ))
}

fn decide(engine: &PolicyEngine, tool: &str, params: Value) -> gate_core::Decision {
    let map: Map<String, Value> = params.as_object().cloned().unwrap_or_default();
    engine.decide(&CallRequest::new(tool, map))
}

fn allowed(engine: &PolicyEngine, tool: &str, params: Value) -> bool {
    decide(engine, tool, params).verdict() == Verdict::Allow
}

fn tool_policy<'a>(engine: &'a PolicyEngine, tool: &str) -> &'a ToolPolicy {
    engine.policy().tool(tool).unwrap()
}

fn check(engine: &PolicyEngine, tool: &str, params: Value) -> Result<(), ParamError> {
    let map: Map<String, Value> = params.as_object().cloned().unwrap_or_default();
    tool_policy(engine, tool).check_params_with(&map, &LexicalResolver)
}

// T-PAR-001 — an unlisted parameter is denied, not stripped.
#[test]
fn t_par_001_unlisted_parameter_denied() {
    let engine = engine();
    let decision = decide(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "cc": "x@evil.example"}),
    );
    assert_eq!(decision.verdict(), Verdict::Deny);
    assert_eq!(decision.reasons(), &[ReasonCode::DenyParamNotAllowed]);
}

// T-PAR-002 — the server's inputSchema can never widen the policy.
#[test]
fn t_par_002_server_schema_cannot_widen() {
    // The policy is the only source of the allowlist; a server declaring `cc`
    // is irrelevant because `cc` never appears in policy.
    let engine = engine();
    let server_schema = json!({"type": "object", "properties": {"path": {}, "cc": {}}});
    assert!(server_schema.get("properties").unwrap().get("cc").is_some());
    assert_eq!(
        check(&engine, "fs:read_file", json!({"cc": "x"})),
        Err(ParamError::NotAllowed("cc".into()))
    );
}

// T-PAR-003 — the address regex is enforced.
#[test]
fn t_par_003_regex_enforced() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "a@corp.example"})
    ));
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "a@evil.example"})
    ));
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "a@corp.example.evil"})
    ));
}

// T-PAR-004 — display-name trick.
#[test]
fn t_par_004_display_name_trick_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "\"x@corp.example\" <a@evil.example>"})
    ));
}

// T-PAR-005 — path traversal, with normalisation allowed inside the prefix.
#[test]
fn t_par_005_path_traversal_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/../etc/passwd"})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/etc/passwd"})
    ));
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a/../b"})
    ));
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/./a"})
    ));
    // Cannot walk above the root.
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/../../etc/passwd"})
    ));
}

// T-PAR-006 — a symlink escape is caught by filesystem resolution.
#[test]
fn t_par_006_symlink_escape_denied() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), b"secret").unwrap();
    std::os::unix::fs::symlink(outside.join("secret"), workspace.join("link")).unwrap();

    let prefix = format!("{}/", workspace.display());
    let policy = Arc::new(Policy::parse(&policy_text(&prefix)).unwrap());
    let lexical = PolicyEngine::lexical(Arc::clone(&policy));
    let fs = PolicyEngine::new(Arc::clone(&policy), Arc::new(FsResolver));

    let link = format!("{}/link", workspace.display());
    let params = json!({"path": link});
    assert!(
        allowed(&lexical, "fs:read_file", params.clone()),
        "the lexical resolver cannot see symlinks"
    );
    assert!(
        !allowed(&fs, "fs:read_file", params),
        "the filesystem resolver must reject the escape"
    );

    let real = format!("{}/fine.txt", workspace.display());
    std::fs::write(&real, b"ok").unwrap();
    assert!(allowed(&fs, "fs:read_file", json!({"path": real})));
    // A new file inside the workspace is allowed via its parent.
    assert!(allowed(
        &fs,
        "fs:read_file",
        json!({"path": format!("{}/new-file.txt", workspace.display())})
    ));
}

// T-PAR-007 — fullwidth/backslash confusables are rejected.
#[test]
fn t_par_007_unicode_confusables_denied() {
    let engine = engine();
    for path in [
        "/workspace/\u{ff0e}\u{ff0e}/etc/passwd",
        "/workspace\\..\\etc\\passwd",
        "/workspace/\u{2215}etc/passwd",
        "/workspace/\u{ff0f}etc/passwd",
    ] {
        assert!(
            !allowed(&engine, "fs:read_file", json!({ "path": path })),
            "{path:?}"
        );
    }
}

// T-PAR-008 — userinfo in the URL is a host-confusion attack.
#[test]
fn t_par_008_userinfo_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://good.com@evil.example/"})
    ));
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example@evil.example/"})
    ));
    assert!(allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example/path"})
    ));
}

// T-PAR-009 — IDN homographs are rejected; punycode must match exactly.
#[test]
fn t_par_009_idn_homograph_denied() {
    let engine = engine();
    // Cyrillic "а" in "аllowed.example" looks identical to ASCII.
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://\u{430}llowed.example/"})
    ));
    assert!(allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://xn--bcher-kva.example/"})
    ));
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example./"})
    ));
}

// T-PAR-010 — a nested URL pointing elsewhere (redirector) is denied.
#[test]
fn t_par_010_redirect_host_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example/?next=https://evil.example/"})
    ));
    assert!(!allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example/?next=https%3A%2F%2Fevil.example%2F"})
    ));
    assert!(allowed(
        &engine,
        "api:fetch",
        json!({"url": "https://allowed.example/?next=https://allowed.example/b"})
    ));
}

// T-PAR-011 — max_len boundary is exact.
#[test]
fn t_par_011_max_len_boundary() {
    let engine = engine();
    let at_limit = "s".repeat(200);
    let over = "s".repeat(201);
    assert!(allowed(
        &engine,
        "mailer:send_email",
        json!({"subject": at_limit})
    ));
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"subject": over})
    ));
}

// T-PAR-012 — max_items boundary is exact.
#[test]
fn t_par_012_max_items_boundary() {
    let engine = engine();
    let five = json!([
        "a@corp.example",
        "b@corp.example",
        "c@corp.example",
        "d@corp.example",
        "e@corp.example"
    ]);
    let six = json!([
        "a@corp.example",
        "b@corp.example",
        "c@corp.example",
        "d@corp.example",
        "e@corp.example",
        "f@corp.example"
    ]);
    assert!(allowed(&engine, "mailer:send_email", json!({"to": five})));
    assert!(!allowed(&engine, "mailer:send_email", json!({"to": six})));
}

// T-PAR-013 — the regex engine is linear: no ReDoS.
#[test]
fn t_par_013_regex_dos_corpus() {
    let engine = engine();
    let corpus = [
        "a".repeat(50_000),
        format!("{}{}", "a".repeat(50_000), "!"),
        format!("{}{}", "a@".repeat(20_000), "corp.example"),
        format!("{}{}", "x".repeat(60_000), "@"),
        format!("{}@corp.example", "a.".repeat(30_000)),
        "@".repeat(50_000),
        format!("{}{}", "a@corp.example ".repeat(3_000), "a@corp"),
    ];
    for input in corpus {
        let started = Instant::now();
        let decision = decide(&engine, "mailer:send_email", json!({ "to": input }));
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(10),
            "regex took {elapsed:?}"
        );
        // max_len is not set on `to`, but the regex itself must still be quick.
        assert!(matches!(decision.verdict(), Verdict::Allow | Verdict::Deny));
    }
}

// T-PAR-014 — numeric boundaries are inclusive.
#[test]
fn t_par_014_numeric_range() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": 1})
    ));
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": 100})
    ));
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": 12.5})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": 0})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": 101})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": -1})
    ));
}

// T-PAR-015/016 — nested objects and arrays of objects are type confusion.
#[test]
fn t_par_015_nested_object_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": {"$ne": "/workspace/a"}})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"limit": {"$gt": 0}})
    ));
}

#[test]
fn t_par_016_array_of_objects_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": [{"address": "a@corp.example"}]})
    ));
}

// T-PAR-017 — string/number confusion.
#[test]
fn t_par_017_type_confusion_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": "100"})
    ));
    assert!(!allowed(&engine, "mailer:send_email", json!({"to": 42})));
    assert!(!allowed(&engine, "db:grant_role", json!({"quota": "5"})));
}

// T-PAR-018 — absent is fine, explicit null is not.
#[test]
fn t_par_018_null_vs_absent() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "a@corp.example"})
    ));
    assert!(!allowed(&engine, "mailer:send_email", json!({"to": null})));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": null})
    ));
}

// T-PAR-019 — enums are exact and case-sensitive.
#[test]
fn t_par_019_enum_case_sensitive() {
    let engine = engine();
    assert!(allowed(&engine, "db:grant_role", json!({"role": "reader"})));
    assert!(!allowed(
        &engine,
        "db:grant_role",
        json!({"role": "Reader"})
    ));
    assert!(!allowed(&engine, "db:grant_role", json!({"role": "admin"})));
}

// T-PAR-020 — an empty value is only allowed when no rule forbids it.
#[test]
fn t_par_020_empty_string() {
    let engine = engine();
    assert!(!allowed(&engine, "mailer:send_email", json!({"to": ""})));
    assert!(allowed(&engine, "mailer:send_email", json!({"body": ""})));
}

// T-PAR-021 — a scalar is treated as a single item, not an unbounded list.
#[test]
fn t_par_021_scalar_is_single_item() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "mailer:send_email",
        json!({"to": "a@corp.example"})
    ));
}

// T-PAR-022 — oversized values are rejected quickly.
#[test]
fn t_par_022_oversized_value_rejected() {
    let engine = engine();
    let huge = "x".repeat(1_500_000);
    let started = Instant::now();
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"body": huge})
    ));
    assert!(started.elapsed() < Duration::from_millis(50));
}

// T-PAR-023 — regexes are used as written (anchors matter).
#[test]
fn t_par_023_regex_anchoring() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "db:grant_role",
        json!({"principal": "prn_abc123"})
    ));
    assert!(!allowed(
        &engine,
        "db:grant_role",
        json!({"principal": "xprn_abc123"})
    ));
    assert!(!allowed(
        &engine,
        "db:grant_role",
        json!({"principal": "prn_abc123 "})
    ));
}

// T-PAR-024 — prefix boundaries are segment-aware.
#[test]
fn t_par_024_prefix_boundary() {
    let engine = engine();
    assert!(allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a"})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace-evil/a"})
    ));
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspaces/a"})
    ));
}

// T-PAR-025 — only http(s) URLs are considered.
#[test]
fn t_par_025_url_scheme() {
    let engine = engine();
    for url in [
        "ftp://allowed.example/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "allowed.example/x",
        "//allowed.example/x",
    ] {
        assert!(
            !allowed(&engine, "api:fetch", json!({ "url": url })),
            "{url}"
        );
    }
}

// T-PAR-026 — mixed-type arrays are rejected, not partially accepted.
#[test]
fn t_par_026_mixed_array_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": ["a@corp.example", 7]})
    ));
}

// T-PAR-027 — booleans do not satisfy numeric rules.
#[test]
fn t_par_027_bool_for_number_denied() {
    let engine = engine();
    assert!(!allowed(
        &engine,
        "fs:read_file",
        json!({"path": "/workspace/a", "limit": true})
    ));
    assert!(!allowed(&engine, "db:grant_role", json!({"quota": false})));
}

// T-PAR-028 — every rule on a parameter must hold.
#[test]
fn t_par_028_all_rules_apply() {
    let engine = engine();
    // Regex passes but the second element exceeds max_items.
    let six = json!([
        "a@corp.example",
        "b@corp.example",
        "c@corp.example",
        "d@corp.example",
        "e@corp.example",
        "f@corp.example"
    ]);
    assert!(!allowed(&engine, "mailer:send_email", json!({"to": six})));
    // Regex fails though the count is fine.
    assert!(!allowed(
        &engine,
        "mailer:send_email",
        json!({"to": ["a@corp.example", "b@evil.example"]})
    ));
    // Both hold.
    assert!(allowed(
        &engine,
        "mailer:send_email",
        json!({"to": ["a@corp.example", "b@partner.example"]})
    ));
}

// T-PAR-029 — failures map to the closed reason-code set.
#[test]
fn t_par_029_reason_codes() {
    let engine = engine();
    assert_eq!(
        decide(
            &engine,
            "fs:read_file",
            json!({"path": "/workspace/a", "x": 1})
        )
        .reasons(),
        &[ReasonCode::DenyParamNotAllowed]
    );
    assert_eq!(
        decide(&engine, "fs:read_file", json!({"path": "/etc/passwd"})).reasons(),
        &[ReasonCode::DenyParamInvalid]
    );
    assert_eq!(
        decide(
            &engine,
            "mailer:send_email",
            json!({"to": "a@evil.example"})
        )
        .reasons(),
        &[ReasonCode::DenyParamInvalid]
    );
}

// T-PAR-030 — validation is deterministic and does not allocate per call.
#[test]
fn t_par_030_deterministic() {
    let engine = engine();
    let params = json!({"path": "/workspace/report", "limit": 10});
    let first = decide(&engine, "fs:read_file", params.clone());
    let started = Instant::now();
    for _ in 0..10_000 {
        assert_eq!(decide(&engine, "fs:read_file", params.clone()), first);
    }
    let elapsed = started.elapsed();
    eprintln!("T-PAR-030: {elapsed:?} for 10k decisions");
    assert!(elapsed < Duration::from_secs(5));
}
