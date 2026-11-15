//! T-POL-001..020 (plan.md §5.5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use gate_core::{Class, ReasonCode, Verdict};
use gate_policy::{
    CallRequest, DegradePolicy, MetadataHandling, Pin, Policy, PolicyEngine, PolicyError,
};

const EXAMPLE: &str = include_str!("../fixtures/policy.example.toml");

fn policy(text: &str) -> Policy {
    Policy::parse(text).unwrap_or_else(|e| panic!("policy should parse: {e}"))
}

fn engine(text: &str) -> PolicyEngine {
    PolicyEngine::new(Arc::new(policy(text)))
}

fn minimal(tool_extra: &str) -> String {
    format!(
        r#"
[tool."fs:read_file"]
class = "READ_ONLY"
pin = "sha256:4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2"
params_allow = ["path"]
{extra}
[defaults]
default_deny = true
metadata_handling = "delimit"
fail_mode = "closed"
"#,
        extra = tool_extra
    )
}

fn call(tool: &str, params: &[(&str, serde_json::Value)]) -> CallRequest {
    let mut map = serde_json::Map::new();
    for (k, v) in params {
        map.insert((*k).to_owned(), v.clone());
    }
    CallRequest::new(tool, map)
}

// T-POL-001 — the canonical fixture parses.
#[test]
fn t_pol_001_parse_example_policy() {
    let parsed = policy(EXAMPLE);
    assert!(parsed.hash().starts_with("sha256:"));
    assert_eq!(parsed.hash().len(), 71);
    assert_eq!(
        parsed.discoverable_tools(),
        vec!["db:grant_role", "fs:read_file", "mailer:send_email"]
    );
    let mailer = parsed.tool("mailer:send_email").unwrap();
    assert_eq!(mailer.class, Class::ExternalEgress);
    assert!(mailer.requires_endorsement_if_tainted);
    assert_eq!(mailer.endorsement.escalation_cap, 2);
    assert_eq!(mailer.endorsement.delta_t_hours, 24);
    assert_eq!(mailer.params.len(), 3);
    assert!(mailer.params.get("to").unwrap().regex.is_some());
    assert_eq!(mailer.params.get("to").unwrap().max_items, Some(5));
    let fs = parsed.tool("fs:read_file").unwrap();
    assert_eq!(fs.degrade_on_exporter_loss, DegradePolicy::Allow);
    assert_eq!(
        parsed.defaults().metadata_handling,
        MetadataHandling::Delimit
    );
    assert!(parsed.defaults().default_deny);
}

// T-POL-002 — unknown keys are rejected.
#[test]
fn t_pol_002_unknown_keys_rejected() {
    assert!(matches!(
        Policy::parse(&minimal("bogus_param = 1")),
        Err(PolicyError::Invalid { .. })
    ));
    let unknown_top = EXAMPLE.replace("[defaults]", "[bogus]\nx = 1\n\n[defaults]");
    assert!(matches!(
        Policy::parse(&unknown_top),
        Err(PolicyError::UnknownKey(k)) if k == "bogus"
    ));
    let unknown_defaults = EXAMPLE.replace(
        "fail_mode = \"closed\"",
        "fail_mode = \"closed\"\nbogus = true",
    );
    assert!(matches!(
        Policy::parse(&unknown_defaults),
        Err(PolicyError::UnknownKey(k)) if k.starts_with("defaults.")
    ));
}

// T-POL-003 — a tool absent from policy is undiscoverable and denied.
#[test]
fn t_pol_003_absent_tool_denied() {
    let engine = engine(EXAMPLE);
    assert!(!engine
        .policy()
        .discoverable_tools()
        .contains(&"mailer:send_sms"));
    let decision = engine.decide(&call(
        "mailer:send_sms",
        &[("to", serde_json::json!("a@corp.example"))],
    ));
    assert_eq!(decision.verdict(), Verdict::Deny);
    assert!(decision.reasons().contains(&ReasonCode::DenyUnpinned));
}

// T-POL-004 — a missing class is an error.
#[test]
fn t_pol_004_missing_class() {
    let text = minimal("").replace("class = \"READ_ONLY\"\n", "");
    assert_eq!(
        Policy::parse(&text).unwrap_err(),
        PolicyError::Missing("class")
    );
    let text = minimal("").replace("pin = \"sha256:", "# pin removed\n#");
    assert!(Policy::parse(&text).is_err());
}

// T-POL-005 — only READ_ONLY may degrade on exporter loss.
#[test]
fn t_pol_005_degrade_only_for_read_only() {
    let write = r#"
[tool."mailer:send_email"]
class = "EXTERNAL_EGRESS"
pin = "sha256:9f2c1b7d4e6a8c0f2d4b6e8a0c2e4f6a8b0d2f4e6c8a0b2d4f6e8c0a2b4d6f8e"
params_allow = ["to"]
degrade_on_exporter_loss = "allow"

[defaults]
default_deny = true
metadata_handling = "delimit"
fail_mode = "closed"
"#;
    match Policy::parse(write) {
        Err(PolicyError::Invalid { field, .. }) => {
            assert_eq!(field, "degrade_on_exporter_loss")
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

// T-POL-006 — the hash is stable across key reordering and changes with content.
#[test]
fn t_pol_006_policy_hash_stable() {
    let a = policy(EXAMPLE);
    let reordered = format!(
        "{}\n{}",
        r#"[defaults]
fail_mode = "closed"
metadata_handling = "delimit"
default_deny = true

  [defaults.transparency_degraded]
  block_classes = ["PRIVILEGE_GRANTING", "IRREVERSIBLE"]"#,
        EXAMPLE.split("[defaults]").next().unwrap()
    );
    let b = policy(&reordered);
    assert_eq!(a.hash(), b.hash(), "key order must not change the hash");

    let changed = EXAMPLE.replace("escalation_cap = 2", "escalation_cap = 3");
    assert_ne!(a.hash(), policy(&changed).hash());
}

// T-POL-007 — defaults must fail closed.
#[test]
fn t_pol_007_defaults_enforced() {
    let open = minimal("").replace("default_deny = true", "default_deny = false");
    assert!(matches!(
        Policy::parse(&open),
        Err(PolicyError::Invalid { .. })
    ));
    let no_defaults = minimal("").split("[defaults]").next().unwrap().to_owned();
    assert_eq!(
        Policy::parse(&no_defaults).unwrap_err(),
        PolicyError::Missing("defaults")
    );
}

// T-POL-008 — invalid regex is rejected at parse time.
#[test]
fn t_pol_008_invalid_regex() {
    let text = minimal("  [tool.\"fs:read_file\".path]\n  match = '([unclosed'");
    assert!(matches!(
        Policy::parse(&text),
        Err(PolicyError::Invalid { field, .. }) if field.ends_with(".match")
    ));
}

// T-POL-009 — limits are bounded.
#[test]
fn t_pol_009_limits_bounded() {
    let too_long = minimal("  [tool.\"fs:read_file\".path]\n  max_len = 2000000");
    assert!(Policy::parse(&too_long).is_err());
    let zero_items = minimal("  [tool.\"fs:read_file\".path]\n  max_items = 0");
    assert!(Policy::parse(&zero_items).is_err());
    let ok = minimal("  [tool.\"fs:read_file\".path]\n  max_len = 4096\n  max_items = 8");
    assert!(Policy::parse(&ok).is_ok());
}

// T-POL-010 — duplicate tool entries are rejected.
#[test]
fn t_pol_010_duplicate_tool() {
    let text = format!("{EXAMPLE}\n[tool.\"fs:read_file\"]\nclass = \"READ_ONLY\"\n");
    assert!(matches!(Policy::parse(&text), Err(PolicyError::Toml(_))));
}

// T-POL-011 — unknown class names are rejected.
#[test]
fn t_pol_011_invalid_class() {
    let text = minify_class("READ_WRITE");
    assert!(matches!(
        Policy::parse(&text),
        Err(PolicyError::Invalid { field, .. }) if field == "class"
    ));
    assert!(Policy::parse(&minify_class("READ_ONLY")).is_ok());
}

fn minify_class(class: &str) -> String {
    minimal("").replace("class = \"READ_ONLY\"", &format!("class = \"{class}\""))
}

// T-POL-012/013 — pin format.
#[test]
fn t_pol_012_pin_format() {
    assert!(Pin::parse("sha256:4b81").is_err());
    assert!(
        Pin::parse("4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2").is_err()
    );
    assert!(
        Pin::parse("sha256:4B81E2C9A7D5F3B1E8C6A4D2F0B8E6C4A2D0F8E6B4C2A0D8F6E4B2C0A8D6F4E2")
            .is_err()
    );
    let ok = Pin::parse("sha256:4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2")
        .unwrap();
    assert!(ok.as_str().starts_with("sha256:"));
}

#[test]
fn t_pol_013_pin_required() {
    let text = minimal("").replace(
        "pin = \"sha256:4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2\"",
        "",
    );
    assert_eq!(
        Policy::parse(&text).unwrap_err(),
        PolicyError::Missing("pin")
    );
}

// T-POL-014 — explicit deny is allowed for READ_ONLY.
#[test]
fn t_pol_014_degrade_deny_allowed() {
    let text = minimal("degrade_on_exporter_loss = \"deny\"");
    let parsed = policy(&text);
    assert_eq!(
        parsed
            .tool("fs:read_file")
            .unwrap()
            .degrade_on_exporter_loss,
        DegradePolicy::Deny
    );
}

// T-POL-015/016 — parameter rule keys and references.
#[test]
fn t_pol_015_param_rule_unknown_key() {
    let text = minimal("  [tool.\"fs:read_file\".path]\n  regex = 'x'");
    assert!(
        matches!(Policy::parse(&text), Err(PolicyError::UnknownKey(k)) if k.ends_with(".regex"))
    );
}

#[test]
fn t_pol_016_param_rule_must_be_allowed() {
    let text = minimal("  [tool.\"fs:read_file\".other]\n  max_len = 10");
    assert!(
        matches!(Policy::parse(&text), Err(PolicyError::Invalid { field, .. }) if field.contains(".other"))
    );
}

// T-POL-017 — an allowlisted parameter may have no rule (presence-checked only).
#[test]
fn t_pol_017_allowlisted_param_without_rule() {
    let parsed = policy(&minimal(""));
    assert!(parsed
        .tool("fs:read_file")
        .unwrap()
        .params
        .contains_key("path"));
    assert!(parsed.tool("fs:read_file").unwrap().params["path"]
        .max_len
        .is_none());
}

// T-POL-018 — blanket allow is forbidden for irreversible classes.
#[test]
fn t_pol_018_blanket_allow_forbidden() {
    let irreversible = r#"
[tool."db:drop"]
class = "IRREVERSIBLE"
pin = "sha256:1a3c5e7b9d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c"
params_allow = ["table"]
  [tool."db:drop".endorsement]
  blanket_allow = true

[defaults]
default_deny = true
metadata_handling = "delimit"
fail_mode = "closed"
"#;
    assert!(matches!(
        Policy::parse(irreversible),
        Err(PolicyError::Invalid { field, .. }) if field == "endorsement.blanket_allow"
    ));
    let idempotent = irreversible
        .replace("db:drop", "cache:clear")
        .replace("IRREVERSIBLE", "IDEMPOTENT_WRITE");
    assert!(Policy::parse(&idempotent).is_ok());
}

// T-POL-019 — endorsement bounds.
#[test]
fn t_pol_019_endorsement_bounds() {
    let make = |cap: i64, delta: &str| {
        minimal(&format!(
            "  [tool.\"fs:read_file\".endorsement]\n  escalation_cap = {cap}\n  delta_t = \"{delta}\""
        ))
    };
    assert!(Policy::parse(&make(0, "24h")).is_err());
    assert!(Policy::parse(&make(101, "24h")).is_err());
    assert!(Policy::parse(&make(5, "0h")).is_err());
    assert!(Policy::parse(&make(5, "31d")).is_err());
    assert!(Policy::parse(&make(5, "abc")).is_err());
    let ok = policy(&make(5, "30d"));
    assert_eq!(
        ok.tool("fs:read_file").unwrap().endorsement.delta_t_hours,
        720
    );
}

// T-POL-020 — fail mode, metadata handling, transparency defaults.
#[test]
fn t_pol_020_defaults_validated() {
    let open = minimal("").replace("fail_mode = \"closed\"", "fail_mode = \"open\"");
    assert!(
        matches!(Policy::parse(&open), Err(PolicyError::Invalid { field, .. }) if field == "defaults.fail_mode")
    );
    let metadata = minimal("").replace(
        "metadata_handling = \"delimit\"",
        "metadata_handling = \"trust\"",
    );
    assert!(matches!(
        Policy::parse(&metadata),
        Err(PolicyError::Invalid { field, .. }) if field == "defaults.metadata_handling"
    ));
    let unknown = minimal("").replace(
        "fail_mode = \"closed\"",
        "fail_mode = \"closed\"\n\n[defaults.transparency_degraded]\nbogus = []",
    );
    let normalize = |e: PolicyError| match e {
        PolicyError::UnknownKey(k) => k,
        other => panic!("expected UnknownKey, got {other:?}"),
    };
    assert!(normalize(Policy::parse(&unknown).unwrap_err())
        .starts_with("defaults.transparency_degraded."));
}

// Engine behaviour available at M1: pinned + allowlisted parameters only.
#[test]
fn engine_allows_pinned_tool_with_allowlisted_params() {
    let engine = engine(EXAMPLE);
    let decision = engine.decide(&call(
        "fs:read_file",
        &[("path", serde_json::json!("/workspace/report.txt"))],
    ));
    assert_eq!(decision.verdict(), Verdict::Allow);
    assert_eq!(decision.reasons(), &[ReasonCode::AllowPolicy]);
}

#[test]
fn engine_denies_unlisted_parameter_instead_of_stripping_it() {
    let engine = engine(EXAMPLE);
    let decision = engine.decide(&call(
        "fs:read_file",
        &[
            ("path", serde_json::json!("/workspace/a")),
            ("cc", serde_json::json!("attacker@evil.example")),
        ],
    ));
    assert_eq!(decision.verdict(), Verdict::Deny);
    assert_eq!(decision.reasons(), &[ReasonCode::DenyParamNotAllowed]);
}

#[test]
fn engine_decision_is_deterministic() {
    let engine = engine(EXAMPLE);
    let request = call(
        "mailer:send_email",
        &[("to", serde_json::json!("a@corp.example"))],
    );
    let first = engine.decide(&request);
    for _ in 0..16 {
        assert_eq!(engine.decide(&request), first);
    }
}
