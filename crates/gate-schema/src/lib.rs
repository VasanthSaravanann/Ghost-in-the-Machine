//! gate-schema — descriptor pinning, drift detection and quarantine
//! (plan.md M1-T03, P1-R8..R10, INV-11).
//!
//! `pin = H(JCS(descriptor))` over name, description, inputSchema, annotations
//! and server identity. A descriptor that changes after first sight is
//! **quarantined**, never auto-adopted; `tools/list_changed` cannot widen
//! anything. Un-quarantining requires an out-of-band principal entry, which is a
//! distinct audit event (T-SCH-006) — nothing an MCP message can trigger.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::BTreeMap;

pub mod metadata;

pub use metadata::{
    sanitise, MetadataMode, Namespace, Sanitised, BEGIN_MARKER, END_MARKER, MAX_METADATA_CHARS,
};

use gate_core::{GateError, PrincipalId, ReasonCode};
use gate_crypto::sha256_hex;
use serde::{Deserialize, Serialize};

/// A tool descriptor as the server advertises it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    pub server: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub annotations: BTreeMap<String, String>,
    pub version: String,
}

impl Descriptor {
    /// `server:tool` — the namespaced identity (P1-R12, full isolation in M1-T04).
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.server, self.name)
    }

    /// Canonical bytes: key order in the source is irrelevant, byte content is not.
    pub fn canonical_json(&self) -> Result<String, GateError> {
        let json = serde_json::to_string(self).map_err(|e| GateError::Jcs(e.to_string()))?;
        gate_jcs::canonicalize(&json).map_err(|e| GateError::Jcs(e.to_string()))
    }

    /// `pin_id = H(JCS(descriptor))` (P1-R8).
    pub fn pin(&self) -> Result<String, GateError> {
        Ok(sha256_hex(self.canonical_json()?.as_bytes()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    FirstPin,
    Drift,
    Quarantined,
    Reapproved,
    QuarantineHeld,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: AuditKind,
    pub key: String,
    pub pin: String,
    pub observed: Option<String>,
    pub principal: Option<PrincipalId>,
    pub at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    UnknownTool,
    Quarantined { key: String },
    Drifted { expected: String, observed: String },
    PinMismatch { policy: String, observed: String },
    NotPrincipalAuthorised,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTool => f.write_str("tool is not pinned"),
            Self::Quarantined { key } => write!(f, "tool {key} is quarantined"),
            Self::Drifted { expected, observed } => {
                write!(
                    f,
                    "descriptor drifted: pinned {expected}, observed {observed}"
                )
            }
            Self::PinMismatch { policy, observed } => {
                write!(
                    f,
                    "policy pin {policy} does not match descriptor {observed}"
                )
            }
            Self::NotPrincipalAuthorised => {
                f.write_str("re-approval requires an out-of-band principal entry")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

impl SchemaError {
    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::UnknownTool | Self::PinMismatch { .. } => ReasonCode::DenyUnpinned,
            Self::Quarantined { .. } => ReasonCode::DenyDrift,
            Self::Drifted { .. } => ReasonCode::DenyDrift,
            Self::NotPrincipalAuthorised => ReasonCode::DenyFailClosed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observe {
    /// Same descriptor as the pin.
    Unchanged,
    /// First sight: the pin was recorded.
    FirstPin { pin: String },
    /// Descriptor changed; the tool is now quarantined and useless until
    /// re-approved (T-SCH-002..005).
    Drifted { expected: String, observed: String },
    /// Drift observed while already quarantined.
    QuarantineHeld { expected: String },
}

#[derive(Clone, Debug)]
struct Entry {
    pin: String,
    quarantined: bool,
    last_observed: String,
}

/// Registry of pinned descriptors. Deterministic; no clock/RNG beyond the
/// caller-supplied `at_ms`.
#[derive(Clone, Debug, Default)]
pub struct DescriptorRegistry {
    entries: BTreeMap<String, Entry>,
    audit: Vec<AuditEvent>,
}

impl DescriptorRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a descriptor (first sight, re-list, or `tools/list_changed`).
    /// Drift always quarantines; nothing is ever auto-adopted.
    pub fn observe(&mut self, descriptor: &Descriptor, at_ms: i64) -> Result<Observe, GateError> {
        let key = descriptor.key();
        let observed = descriptor.pin()?;
        match self.entries.get_mut(&key) {
            None => {
                self.entries.insert(
                    key.clone(),
                    Entry {
                        pin: observed.clone(),
                        quarantined: false,
                        last_observed: observed.clone(),
                    },
                );
                self.audit.push(AuditEvent {
                    kind: AuditKind::FirstPin,
                    key,
                    pin: observed.clone(),
                    observed: None,
                    principal: None,
                    at_ms,
                });
                Ok(Observe::FirstPin { pin: observed })
            }
            Some(entry) => {
                entry.last_observed = observed.clone();
                let expected = entry.pin.clone();
                // Quarantine is checked FIRST: a descriptor that reverts to the
                // pinned bytes is still quarantined and must not report
                // `Unchanged` (T-SCH-013).
                if entry.quarantined {
                    self.audit.push(AuditEvent {
                        kind: AuditKind::QuarantineHeld,
                        key,
                        pin: expected.clone(),
                        observed: Some(observed),
                        principal: None,
                        at_ms,
                    });
                    return Ok(Observe::QuarantineHeld { expected });
                }
                if entry.pin == observed {
                    return Ok(Observe::Unchanged);
                }
                entry.quarantined = true;
                self.audit.push(AuditEvent {
                    kind: AuditKind::Drift,
                    key: key.clone(),
                    pin: expected.clone(),
                    observed: Some(observed.clone()),
                    principal: None,
                    at_ms,
                });
                self.audit.push(AuditEvent {
                    kind: AuditKind::Quarantined,
                    key,
                    pin: expected.clone(),
                    observed: Some(observed.clone()),
                    principal: None,
                    at_ms,
                });
                Ok(Observe::Drifted { expected, observed })
            }
        }
    }

    /// Re-approval is out-of-band only: it takes a principal identity and writes
    /// an audit event distinct from a normal pin (T-SCH-006/007).
    pub fn reapprove_out_of_band(
        &mut self,
        key: &str,
        new_pin: &str,
        principal: &PrincipalId,
        at_ms: i64,
    ) -> Result<(), SchemaError> {
        if principal.as_str().is_empty() {
            return Err(SchemaError::NotPrincipalAuthorised);
        }
        let Some(entry) = self.entries.get_mut(key) else {
            return Err(SchemaError::UnknownTool);
        };
        entry.pin = new_pin.to_owned();
        entry.quarantined = false;
        self.audit.push(AuditEvent {
            kind: AuditKind::Reapproved,
            key: key.to_owned(),
            pin: new_pin.to_owned(),
            observed: None,
            principal: Some(principal.clone()),
            at_ms,
        });
        Ok(())
    }

    /// Invocation gate: pinned, not quarantined, and matching the policy pin.
    pub fn invoke_allowed(
        &self,
        key: &str,
        policy_pin: Option<&str>,
    ) -> Result<String, SchemaError> {
        let Some(entry) = self.entries.get(key) else {
            return Err(SchemaError::UnknownTool);
        };
        if entry.quarantined {
            return Err(SchemaError::Quarantined {
                key: key.to_owned(),
            });
        }
        if let Some(policy) = policy_pin {
            if policy != entry.pin {
                return Err(SchemaError::PinMismatch {
                    policy: policy.to_owned(),
                    observed: entry.pin.clone(),
                });
            }
        }
        Ok(entry.pin.clone())
    }

    /// Tools discoverable to the model: pinned and un-quarantined only.
    #[must_use]
    pub fn discoverable(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.quarantined)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    #[must_use]
    pub fn is_quarantined(&self, key: &str) -> bool {
        self.entries.get(key).is_some_and(|e| e.quarantined)
    }

    #[must_use]
    pub fn pin_of(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|e| e.pin.as_str())
    }

    #[must_use]
    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    #[must_use]
    pub fn drift_count(&self) -> usize {
        self.audit
            .iter()
            .filter(|e| e.kind == AuditKind::Drift)
            .count()
    }
}
