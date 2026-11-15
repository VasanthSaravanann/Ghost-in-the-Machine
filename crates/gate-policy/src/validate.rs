//! Parameter allowlist validators (plan.md M1-T02, T-PAR-001..030).
//!
//! Rules only ever *narrow* what the policy already allowed: an unlisted
//! parameter is denied, never stripped. Every check fails closed on type
//! confusion, on null, and on paths/URLs that cannot be proven safe.
//!
//! Path resolution is injected ([`PathResolver`]) because deciding whether a
//! path escapes its prefix is a filesystem question: the lexical resolver is
//! used for pure tests, [`FsResolver`] is what the binary must wire in.

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]

use std::fmt;

use serde_json::{Map, Value};

use crate::{ParamRule, ToolPolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamError {
    NotAllowed(String),
    Invalid(String),
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAllowed(name) => write!(f, "parameter {name:?} is not allowed by policy"),
            Self::Invalid(name) => write!(f, "parameter {name:?} failed validation"),
        }
    }
}

impl std::error::Error for ParamError {}

/// Maps a caller-supplied path to the path that will actually be touched.
pub trait PathResolver: Send + Sync {
    fn canonicalize(&self, path: &str) -> Option<String>;
}

/// Pure lexical resolution: collapses `.`/`..` without touching the filesystem.
#[derive(Debug, Default)]
pub struct LexicalResolver;

impl PathResolver for LexicalResolver {
    fn canonicalize(&self, path: &str) -> Option<String> {
        if !path.starts_with('/') {
            return None;
        }
        let mut segments: Vec<&str> = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop()?;
                }
                other => segments.push(other),
            }
        }
        Some(format!("/{}", segments.join("/")))
    }
}

/// Filesystem resolution: symlinks are followed, so a symlink pointing outside
/// the allowed prefix is rejected. New files are resolved through their parent.
#[derive(Debug, Default)]
pub struct FsResolver;

impl PathResolver for FsResolver {
    fn canonicalize(&self, path: &str) -> Option<String> {
        if !path.starts_with('/') {
            return None;
        }
        if let Ok(canonical) = std::fs::canonicalize(path) {
            return Some(canonical.to_string_lossy().into_owned());
        }
        let parent = std::path::Path::new(path).parent()?;
        let name = std::path::Path::new(path).file_name()?;
        let canonical_parent = std::fs::canonicalize(parent).ok()?;
        Some(canonical_parent.join(name).to_string_lossy().into_owned())
    }
}

impl ParamRule {
    /// Validate one parameter value against this rule.
    pub fn validate(
        &self,
        name: &str,
        value: &Value,
        resolver: &dyn PathResolver,
    ) -> Result<(), ParamError> {
        match value {
            // Absent is fine; explicit null is type confusion (T-PAR-018).
            Value::Null => Err(ParamError::Invalid(name.to_owned())),
            Value::String(text) => self.validate_string(name, text, resolver),
            Value::Array(items) => {
                if self.min.is_some() || self.max.is_some() {
                    // A numeric rule never applies to a list.
                    return Err(ParamError::Invalid(name.to_owned()));
                }
                if let Some(max) = self.max_items {
                    if items.len() > max {
                        return Err(ParamError::Invalid(name.to_owned()));
                    }
                }
                for item in items {
                    match item {
                        Value::String(text) => self.validate_string(name, text, resolver)?,
                        _ if self.has_string_constraints() || self.min.is_some() => {
                            return Err(ParamError::Invalid(name.to_owned()))
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            Value::Number(number) => {
                if self.has_string_constraints() || self.max_items.is_some() {
                    return Err(ParamError::Invalid(name.to_owned()));
                }
                let value = number
                    .as_f64()
                    .ok_or_else(|| ParamError::Invalid(name.to_owned()))?;
                if let Some(min) = self.min {
                    if value < min {
                        return Err(ParamError::Invalid(name.to_owned()));
                    }
                }
                if let Some(max) = self.max {
                    if value > max {
                        return Err(ParamError::Invalid(name.to_owned()));
                    }
                }
                Ok(())
            }
            Value::Bool(_) | Value::Object(_) => {
                if self.has_string_constraints()
                    || self.min.is_some()
                    || self.max.is_some()
                    || self.max_items.is_some()
                {
                    Err(ParamError::Invalid(name.to_owned()))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn has_string_constraints(&self) -> bool {
        self.regex.is_some()
            || self.enum_values.is_some()
            || self.prefix_allow.is_some()
            || self.host_allow.is_some()
            || self.max_len.is_some()
    }

    fn validate_string(
        &self,
        name: &str,
        text: &str,
        resolver: &dyn PathResolver,
    ) -> Result<(), ParamError> {
        if self.min.is_some() || self.max.is_some() {
            // A numeric range never accepts a string.
            return Err(ParamError::Invalid(name.to_owned()));
        }
        if let Some(max) = self.max_len {
            if text.len() > max {
                return Err(ParamError::Invalid(name.to_owned()));
            }
        }
        if let Some(regex) = &self.regex {
            if !regex.is_match(text) {
                return Err(ParamError::Invalid(name.to_owned()));
            }
        }
        if let Some(values) = &self.enum_values {
            if !values.iter().any(|allowed| allowed == text) {
                return Err(ParamError::Invalid(name.to_owned()));
            }
        }
        if let Some(prefixes) = &self.prefix_allow {
            check_path_prefix(name, text, prefixes, resolver)?;
        }
        if let Some(hosts) = &self.host_allow {
            check_url_host(name, text, hosts)?;
        }
        Ok(())
    }
}

impl ToolPolicy {
    /// Strict allowlist + value validation. Unlisted ⇒ [`ParamError::NotAllowed`].
    pub fn check_params_with(
        &self,
        params: &Map<String, Value>,
        resolver: &dyn PathResolver,
    ) -> Result<(), ParamError> {
        for (name, value) in params {
            let Some(rule) = self.params.get(name) else {
                return Err(ParamError::NotAllowed(name.clone()));
            };
            rule.validate(name, value, resolver)?;
        }
        Ok(())
    }
}

/// Characters that look like separators but are not: rejecting them prevents
/// fullwidth-dot and backslash path confusion (T-PAR-007).
const CONFUSABLES: &[char] = &['\u{ff0e}', '\u{ff0f}', '\u{ff3c}', '\u{2215}', '\u{2044}'];

fn check_path_prefix(
    name: &str,
    text: &str,
    prefixes: &[String],
    resolver: &dyn PathResolver,
) -> Result<(), ParamError> {
    let invalid = || ParamError::Invalid(name.to_owned());
    if text.is_empty()
        || text.contains('\0')
        || text.contains('\\')
        || text.chars().any(|c| c.is_control())
        || text.chars().any(|c| CONFUSABLES.contains(&c))
    {
        return Err(invalid());
    }
    let canonical = resolver.canonicalize(text).ok_or_else(invalid)?;
    for prefix in prefixes {
        let prefix = resolver
            .canonicalize(prefix)
            .unwrap_or_else(|| prefix.clone());
        let root = if prefix.ends_with('/') {
            prefix
        } else {
            format!("{prefix}/")
        };
        if canonical.starts_with(&root) || canonical == root.trim_end_matches('/') {
            return Ok(());
        }
    }
    Err(invalid())
}

/// Host allowlist for URL-valued parameters (T-PAR-008..010).
///
/// * only `http`/`https`;
/// * no userinfo (`https://good.com@evil.com/` is rejected);
/// * the host must be ASCII: an IDN homograph can therefore never equal an
///   ASCII/punycode allowlist entry;
/// * a nested absolute URL in the query string must also target an allowed
///   host, so a redirector cannot be used to reach one that is not.
fn check_url_host(name: &str, text: &str, allowed: &[String]) -> Result<(), ParamError> {
    let invalid = || ParamError::Invalid(name.to_owned());
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))
        .ok_or_else(invalid)?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end).ok_or_else(invalid)?;
    if authority.contains('@') || authority.is_empty() {
        return Err(invalid());
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty()
        || !host.is_ascii()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err(invalid());
    }
    if !allowed.iter().any(|a| a.eq_ignore_ascii_case(host)) {
        return Err(invalid());
    }
    if let Some((_, query)) = rest.split_once('?') {
        for pair in query.split('&') {
            let Some((_, value)) = pair.split_once('=') else {
                continue;
            };
            let decoded = value
                .replace("%3A", ":")
                .replace("%3a", ":")
                .replace("%2F", "/")
                .replace("%2f", "/");
            let nested = decoded
                .strip_prefix("https://")
                .or_else(|| decoded.strip_prefix("http://"));
            if let Some(nested) = nested {
                let nested_host = nested.split(['/', '?', '#']).next().unwrap_or(nested);
                if !allowed.iter().any(|a| a.eq_ignore_ascii_case(nested_host)) {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}
