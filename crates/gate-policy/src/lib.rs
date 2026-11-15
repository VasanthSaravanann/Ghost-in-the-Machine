//! gate-policy — TOML policy DSL, capability classes, deterministic
//! `PolicyEngine::decide` (plan.md M1-T01, §9.1).
//!
//! Parsing is strict: unknown keys, missing classes, invalid pins, invalid
//! regexes and unsafe defaults are rejected, because a policy that silently
//! ignores a line is a policy the operator did not approve.
//!
//! Invariant: no model output reaches this crate. `decide` takes a
//! [`CallRequest`] built from the pinned descriptor and the raw tool arguments.

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gate_core::{AuthClosure, Class, Decision, ReasonCode};
use gate_crypto::sha256_hex;
use gate_jcs::canonicalize;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

/// Hard limits, so a hostile policy cannot make the gate unresponsive.
pub const MAX_TOOLS: usize = 4_096;
pub const MAX_PARAMS_PER_TOOL: usize = 64;
pub const MAX_PARAM_LEN_LIMIT: usize = 1_000_000;
pub const MAX_ITEMS_LIMIT: usize = 10_000;
pub const MIN_DELTA_T_HOURS: u32 = 1;
pub const MAX_DELTA_T_HOURS: u32 = 24 * 30;
pub const MAX_ESCALATION_CAP: u32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Toml(String),
    UnknownKey(String),
    Missing(&'static str),
    Invalid { field: String, detail: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(detail) => write!(f, "policy TOML is invalid: {detail}"),
            Self::UnknownKey(key) => write!(f, "unknown policy key: {key}"),
            Self::Missing(field) => write!(f, "missing required policy field: {field}"),
            Self::Invalid { field, detail } => write!(f, "invalid policy field {field}: {detail}"),
        }
    }
}

impl std::error::Error for PolicyError {}

fn invalid(field: impl Into<String>, detail: impl Into<String>) -> PolicyError {
    PolicyError::Invalid {
        field: field.into(),
        detail: detail.into(),
    }
}

/// `sha256:<64 lowercase hex>` descriptor pin (INV-11).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Pin(String);

impl Pin {
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(invalid("pin", "must start with sha256:"));
        };
        if hex.len() != 64
            || !hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(invalid("pin", "must be 64 lowercase hex characters"));
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataHandling {
    Delimit,
    Strip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DegradePolicy {
    Allow,
    Deny,
}

/// Parameter validator set (M1-T01 parses them; M1-T02 enforces values).
#[derive(Clone, Debug, Default, Serialize)]
pub struct ParamRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_source: Option<String>,
    #[serde(skip_serializing)]
    pub regex: Option<Regex>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Endorsement {
    pub escalation_cap: u32,
    /// Bounds checked at parse time (§M3-T01/T-LDG-011): 1 h .. 30 d.
    pub delta_t_hours: u32,
    pub blanket_allow: bool,
}

impl Default for Endorsement {
    fn default() -> Self {
        Self {
            escalation_cap: 5,
            delta_t_hours: 24,
            blanket_allow: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolPolicy {
    pub class: Class,
    pub pin: Pin,
    pub params: BTreeMap<String, ParamRule>,
    pub requires_endorsement_if_tainted: bool,
    pub endorsement: Endorsement,
    pub degrade_on_exporter_loss: DegradePolicy,
}

impl ToolPolicy {
    /// Strict allowlist: an unlisted parameter is *denied*, never stripped
    /// (plan.md M1-T02, T-PAR-001). Value validation lands in M1-T02.
    pub fn check_params(&self, params: &serde_json::Map<String, Value>) -> Result<(), ParamError> {
        for name in params.keys() {
            if !self.params.contains_key(name) {
                return Err(ParamError::NotAllowed(name.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamError {
    NotAllowed(String),
    Invalid(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct TransparencyDefaults {
    /// A set: declaration order must not affect the policy hash (T-POL-006).
    pub block_classes: BTreeSet<Class>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Defaults {
    pub default_deny: bool,
    pub metadata_handling: MetadataHandling,
    pub fail_mode: String,
    pub transparency_degraded: TransparencyDefaults,
}

#[derive(Clone, Debug, Serialize)]
pub struct Policy {
    tools: BTreeMap<String, ToolPolicy>,
    defaults: Defaults,
    /// `sha256:<hex>` of the canonical policy (T-POL-006).
    hash: String,
}

impl Policy {
    /// Parse and validate a policy document. The hash is computed from the
    /// canonicalised parsed structure, so key order in the file is irrelevant.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| PolicyError::Toml(e.message().to_owned()))?;
        let mut tools = BTreeMap::new();

        for (key, value) in &table {
            match key.as_str() {
                "tool" => {
                    let tool_table = value
                        .as_table()
                        .ok_or_else(|| invalid("tool", "must be a table"))?;
                    if tool_table.len() > MAX_TOOLS {
                        return Err(invalid("tool", format!("more than {MAX_TOOLS} tools")));
                    }
                    for (name, tool_value) in tool_table {
                        let tool = parse_tool(name, tool_value)?;
                        if tools.insert(name.clone(), tool).is_some() {
                            return Err(invalid(format!("tool.{name}"), "duplicate tool entry"));
                        }
                    }
                }
                "defaults" => {}
                other => return Err(PolicyError::UnknownKey(other.to_owned())),
            }
        }

        let defaults = match table.get("defaults") {
            Some(value) => parse_defaults(value)?,
            None => return Err(PolicyError::Missing("defaults")),
        };
        if !defaults.default_deny {
            return Err(invalid(
                "defaults.default_deny",
                "must be true (fail closed)",
            ));
        }
        if defaults.fail_mode != "closed" {
            return Err(invalid("defaults.fail_mode", "must be \"closed\""));
        }

        let mut policy = Self {
            tools,
            defaults,
            hash: String::new(),
        };
        policy.hash = policy.compute_hash()?;
        Ok(policy)
    }

    fn compute_hash(&self) -> Result<String, PolicyError> {
        let json = serde_json::to_string(self)
            .map_err(|e| invalid("policy", format!("serialisation failed: {e}")))?;
        let canonical = canonicalize(&json)
            .map_err(|e| invalid("policy", format!("canonicalisation failed: {e}")))?;
        Ok(sha256_hex(canonical.as_bytes()))
    }

    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&ToolPolicy> {
        self.tools.get(name)
    }

    /// Tools the model is allowed to discover: everything in the policy, and
    /// nothing else (T-POL-003).
    #[must_use]
    pub fn discoverable_tools(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn defaults(&self) -> &Defaults {
        &self.defaults
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Namespaced `server:tool` collisions are reported by `gate-schema`; the
    /// policy treats the composite name as the identity.
    #[must_use]
    pub fn tool_names(&self) -> BTreeSet<&str> {
        self.tools.keys().map(String::as_str).collect()
    }
}

fn parse_defaults(value: &toml::Value) -> Result<Defaults, PolicyError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid("defaults", "must be a table"))?;
    for key in table.keys() {
        match key.as_str() {
            "default_deny" | "metadata_handling" | "fail_mode" | "transparency_degraded" => {}
            other => return Err(PolicyError::UnknownKey(format!("defaults.{other}"))),
        }
    }
    let default_deny = table
        .get("default_deny")
        .and_then(toml::Value::as_bool)
        .ok_or(PolicyError::Missing("defaults.default_deny"))?;
    let metadata_handling = match table
        .get("metadata_handling")
        .and_then(toml::Value::as_str)
        .unwrap_or("delimit")
    {
        "delimit" => MetadataHandling::Delimit,
        "strip" => MetadataHandling::Strip,
        other => return Err(invalid("defaults.metadata_handling", other.to_owned())),
    };
    let fail_mode = table
        .get("fail_mode")
        .and_then(toml::Value::as_str)
        .unwrap_or("closed")
        .to_owned();

    let mut block_classes = BTreeSet::new();
    if let Some(td) = table.get("transparency_degraded") {
        let td = td
            .as_table()
            .ok_or_else(|| invalid("defaults.transparency_degraded", "must be a table"))?;
        for key in td.keys() {
            if key != "block_classes" {
                return Err(PolicyError::UnknownKey(format!(
                    "defaults.transparency_degraded.{key}"
                )));
            }
        }
        if let Some(classes) = td.get("block_classes") {
            let array = classes.as_array().ok_or_else(|| {
                invalid(
                    "defaults.transparency_degraded.block_classes",
                    "must be an array",
                )
            })?;
            for class in array {
                let name = class.as_str().ok_or_else(|| {
                    invalid(
                        "defaults.transparency_degraded.block_classes",
                        "entries must be strings",
                    )
                })?;
                block_classes.insert(parse_class(name)?);
            }
        }
    }
    Ok(Defaults {
        default_deny,
        metadata_handling,
        fail_mode,
        transparency_degraded: TransparencyDefaults { block_classes },
    })
}

fn parse_class(name: &str) -> Result<Class, PolicyError> {
    match name {
        "READ_ONLY" => Ok(Class::ReadOnly),
        "IDEMPOTENT_WRITE" => Ok(Class::IdempotentWrite),
        "EXTERNAL_EGRESS" => Ok(Class::ExternalEgress),
        "IRREVERSIBLE" => Ok(Class::Irreversible),
        "PRIVILEGE_GRANTING" => Ok(Class::PrivilegeGranting),
        other => Err(invalid(
            "class",
            format!("unknown capability class {other:?}"),
        )),
    }
}

const TOOL_KEYS: &[&str] = &[
    "class",
    "pin",
    "params_allow",
    "requires_endorsement_if_tainted",
    "endorsement",
    "degrade_on_exporter_loss",
];

fn parse_tool(name: &str, value: &toml::Value) -> Result<ToolPolicy, PolicyError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid(format!("tool.{name}"), "must be a table"))?;
    let class_name = table
        .get("class")
        .and_then(toml::Value::as_str)
        .ok_or(PolicyError::Missing("class"))?;
    let class = parse_class(class_name)?;
    let pin_name = table
        .get("pin")
        .and_then(toml::Value::as_str)
        .ok_or(PolicyError::Missing("pin"))?;
    let pin = Pin::parse(pin_name)?;

    let params_allow: Vec<String> = table
        .get("params_allow")
        .and_then(toml::Value::as_array)
        .ok_or(PolicyError::Missing("params_allow"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("params_allow", "entries must be strings"))
        })
        .collect::<Result<_, _>>()?;
    if params_allow.len() > MAX_PARAMS_PER_TOOL {
        return Err(invalid(
            "params_allow",
            format!("more than {MAX_PARAMS_PER_TOOL} entries"),
        ));
    }
    if params_allow.iter().any(|p| p.is_empty()) {
        return Err(invalid("params_allow", "entries must not be empty"));
    }

    let requires_endorsement_if_tainted = table
        .get("requires_endorsement_if_tainted")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    let degrade_on_exporter_loss = match table
        .get("degrade_on_exporter_loss")
        .and_then(toml::Value::as_str)
        .unwrap_or("deny")
    {
        "allow" => DegradePolicy::Allow,
        "deny" => DegradePolicy::Deny,
        other => {
            return Err(invalid(
                "degrade_on_exporter_loss",
                format!("must be \"allow\" or \"deny\", got {other:?}"),
            ))
        }
    };
    if degrade_on_exporter_loss == DegradePolicy::Allow && class != Class::ReadOnly {
        // T-POL-005: only READ_ONLY may degrade (R4).
        return Err(invalid(
            "degrade_on_exporter_loss",
            "allowed only for READ_ONLY tools",
        ));
    }

    let endorsement = match table.get("endorsement") {
        Some(value) => parse_endorsement(value)?,
        None => Endorsement::default(),
    };
    if endorsement.blanket_allow && matches!(class, Class::Irreversible | Class::PrivilegeGranting)
    {
        // §M3-T05/T-CHN-003: no "always allow" for irreversible classes.
        return Err(invalid(
            "endorsement.blanket_allow",
            "not allowed for IRREVERSIBLE or PRIVILEGE_GRANTING tools",
        ));
    }

    let allowed: BTreeSet<&str> = params_allow.iter().map(String::as_str).collect();
    // Every allowlisted parameter is present, even without a value rule: the
    // allowlist is the contract, rules only narrow it (T-POL-017).
    let mut params: BTreeMap<String, ParamRule> = params_allow
        .iter()
        .map(|name| (name.clone(), ParamRule::default()))
        .collect();
    for (key, value) in table {
        if TOOL_KEYS.contains(&key.as_str()) {
            continue;
        }
        // Anything else is a parameter rule table.
        if !allowed.contains(key.as_str()) {
            return Err(invalid(
                format!("tool.{name}.{key}"),
                "parameter rule for a parameter that is not in params_allow",
            ));
        }
        params.insert(
            key.clone(),
            parse_param_rule(&format!("tool.{name}.{key}"), value)?,
        );
    }

    Ok(ToolPolicy {
        class,
        pin,
        params,
        requires_endorsement_if_tainted,
        endorsement,
        degrade_on_exporter_loss,
    })
}

fn parse_endorsement(value: &toml::Value) -> Result<Endorsement, PolicyError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid("endorsement", "must be a table"))?;
    for key in table.keys() {
        match key.as_str() {
            "escalation_cap" | "delta_t" | "blanket_allow" => {}
            other => return Err(PolicyError::UnknownKey(format!("endorsement.{other}"))),
        }
    }
    let escalation_cap = match table.get("escalation_cap") {
        Some(v) => {
            let n = v
                .as_integer()
                .ok_or_else(|| invalid("endorsement.escalation_cap", "must be an integer"))?;
            let n = u32::try_from(n)
                .map_err(|_| invalid("endorsement.escalation_cap", "must be non-negative"))?;
            if n == 0 || n > MAX_ESCALATION_CAP {
                return Err(invalid(
                    "endorsement.escalation_cap",
                    format!("must be between 1 and {MAX_ESCALATION_CAP}"),
                ));
            }
            n
        }
        None => Endorsement::default().escalation_cap,
    };
    let delta_t_hours = match table.get("delta_t") {
        Some(v) => {
            let text = v
                .as_str()
                .ok_or_else(|| invalid("endorsement.delta_t", "must be a string like \"24h\""))?;
            parse_delta_t(text)?
        }
        None => Endorsement::default().delta_t_hours,
    };
    let blanket_allow = table
        .get("blanket_allow")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    Ok(Endorsement {
        escalation_cap,
        delta_t_hours,
        blanket_allow,
    })
}

fn parse_delta_t(text: &str) -> Result<u32, PolicyError> {
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let n: u32 = number
        .parse()
        .map_err(|_| invalid("endorsement.delta_t", format!("invalid duration {text:?}")))?;
    let hours = match unit {
        "h" => n,
        "d" => n.saturating_mul(24),
        _ => {
            return Err(invalid(
                "endorsement.delta_t",
                format!("invalid unit in {text:?}"),
            ))
        }
    };
    if !(MIN_DELTA_T_HOURS..=MAX_DELTA_T_HOURS).contains(&hours) {
        return Err(invalid(
            "endorsement.delta_t",
            format!("must be between {MIN_DELTA_T_HOURS}h and {MAX_DELTA_T_HOURS}h"),
        ));
    }
    Ok(hours)
}

const PARAM_KEYS: &[&str] = &[
    "match",
    "enum",
    "min",
    "max",
    "prefix_allow",
    "host_allow",
    "max_len",
    "max_items",
];

fn parse_param_rule(path: &str, value: &toml::Value) -> Result<ParamRule, PolicyError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, "parameter rule must be a table"))?;
    for key in table.keys() {
        if !PARAM_KEYS.contains(&key.as_str()) {
            return Err(PolicyError::UnknownKey(format!("{path}.{key}")));
        }
    }
    let mut rule = ParamRule::default();
    if let Some(pattern) = table.get("match") {
        let source = pattern
            .as_str()
            .ok_or_else(|| invalid(format!("{path}.match"), "must be a string"))?;
        if source.len() > 4_096 {
            return Err(invalid(format!("{path}.match"), "pattern is too long"));
        }
        let compiled =
            Regex::new(source).map_err(|e| invalid(format!("{path}.match"), e.to_string()))?;
        rule.match_source = Some(source.to_owned());
        rule.regex = Some(compiled);
    }
    if let Some(values) = table.get("enum") {
        let array = values
            .as_array()
            .ok_or_else(|| invalid(format!("{path}.enum"), "must be an array"))?;
        if array.len() > 1_000 {
            return Err(invalid(format!("{path}.enum"), "too many values"));
        }
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            out.push(
                item.as_str()
                    .ok_or_else(|| invalid(format!("{path}.enum"), "entries must be strings"))?
                    .to_owned(),
            );
        }
        rule.enum_values = Some(out);
    }
    if let Some(min) = table.get("min") {
        rule.min = Some(
            min.as_float()
                .or_else(|| min.as_integer().map(|i| i as f64))
                .ok_or_else(|| invalid(format!("{path}.min"), "must be a number"))?,
        );
    }
    if let Some(max) = table.get("max") {
        rule.max = Some(
            max.as_float()
                .or_else(|| max.as_integer().map(|i| i as f64))
                .ok_or_else(|| invalid(format!("{path}.max"), "must be a number"))?,
        );
    }
    if let (Some(min), Some(max)) = (rule.min, rule.max) {
        if min > max {
            return Err(invalid(path, "min is greater than max"));
        }
    }
    if let Some(prefixes) = table.get("prefix_allow") {
        let array = prefixes
            .as_array()
            .ok_or_else(|| invalid(format!("{path}.prefix_allow"), "must be an array"))?;
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            out.push(
                item.as_str()
                    .ok_or_else(|| {
                        invalid(format!("{path}.prefix_allow"), "entries must be strings")
                    })?
                    .to_owned(),
            );
        }
        rule.prefix_allow = Some(out);
    }
    if let Some(hosts) = table.get("host_allow") {
        let array = hosts
            .as_array()
            .ok_or_else(|| invalid(format!("{path}.host_allow"), "must be an array"))?;
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            out.push(
                item.as_str()
                    .ok_or_else(|| {
                        invalid(format!("{path}.host_allow"), "entries must be strings")
                    })?
                    .to_owned(),
            );
        }
        rule.host_allow = Some(out);
    }
    if let Some(max_len) = table.get("max_len") {
        let n = max_len
            .as_integer()
            .ok_or_else(|| invalid(format!("{path}.max_len"), "must be an integer"))?;
        let n = usize::try_from(n)
            .map_err(|_| invalid(format!("{path}.max_len"), "must be non-negative"))?;
        if n == 0 || n > MAX_PARAM_LEN_LIMIT {
            return Err(invalid(
                format!("{path}.max_len"),
                format!("must be between 1 and {MAX_PARAM_LEN_LIMIT}"),
            ));
        }
        rule.max_len = Some(n);
    }
    if let Some(max_items) = table.get("max_items") {
        let n = max_items
            .as_integer()
            .ok_or_else(|| invalid(format!("{path}.max_items"), "must be an integer"))?;
        let n = usize::try_from(n)
            .map_err(|_| invalid(format!("{path}.max_items"), "must be non-negative"))?;
        if n == 0 || n > MAX_ITEMS_LIMIT {
            return Err(invalid(
                format!("{path}.max_items"),
                format!("must be between 1 and {MAX_ITEMS_LIMIT}"),
            ));
        }
        rule.max_items = Some(n);
    }
    Ok(rule)
}

// ------------------------------------------------------------------ engine

/// One tool invocation as seen at the transport boundary. Built from the pinned
/// descriptor and the raw arguments; never from model text.
#[derive(Clone, Debug)]
pub struct CallRequest {
    pub tool: String,
    pub params: serde_json::Map<String, Value>,
    /// Inclusive closure of provenance segments the decision depended on.
    pub closure: AuthClosure,
}

impl CallRequest {
    #[must_use]
    pub fn new(tool: impl Into<String>, params: serde_json::Map<String, Value>) -> Self {
        Self {
            tool: tool.into(),
            params,
            closure: AuthClosure::new(),
        }
    }
}

/// Deterministic policy engine (plan.md §2.3). M1 adds pin/allowlist checks;
/// M1-T02 adds value validators; M2-T04 adds the taint pivot.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    policy: Arc<Policy>,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The only output of authorisation. No free text in decisions.
    #[must_use]
    pub fn decide(&self, request: &CallRequest) -> Decision {
        let Some(tool) = self.policy.tool(&request.tool) else {
            return Decision::deny_with(
                vec![ReasonCode::DenyUnpinned, ReasonCode::DenyFailClosed],
                request.closure.clone(),
            );
        };
        match tool.check_params(&request.params) {
            Ok(()) => Decision::allow(vec![ReasonCode::AllowPolicy], request.closure.clone()),
            Err(ParamError::NotAllowed(_)) => Decision::deny_with(
                vec![ReasonCode::DenyParamNotAllowed],
                request.closure.clone(),
            ),
            Err(ParamError::Invalid(_)) => {
                Decision::deny_with(vec![ReasonCode::DenyParamInvalid], request.closure.clone())
            }
        }
    }
}
