//! The single `GateError` → `Decision` mapping (plan.md §2.3, R4).
//!
//! Fail closed: any error in the authorisation path denies for every class
//! except `READ_ONLY`, which may degrade only when policy explicitly allows it.

use crate::{AuthClosure, Class, Decision, GateError, ReasonCode};

/// Whether policy permits a `READ_ONLY` call to proceed when the decision path
/// degraded (`degrade_on_exporter_loss = "allow"`, plan.md §9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExporterLossPolicy {
    Allow,
    Deny,
}

#[must_use]
pub fn reason_for(err: &GateError) -> ReasonCode {
    match err {
        GateError::Jcs(_)
        | GateError::VerificationFailed
        | GateError::ExporterUnavailable
        | GateError::StoreUnavailable(_)
        | GateError::InvalidInput(_)
        | GateError::Unsupported(_)
        | GateError::Internal(_) => ReasonCode::DenyFailClosed,
        GateError::SignerUnavailable => ReasonCode::DenySignerUnavailable,
        GateError::PolicyMissing => ReasonCode::DenyUnpinned,
        GateError::Timeout => ReasonCode::DenyEndorsementTimeout,
    }
}

/// Every authorisation-path failure resolves here (INV-12).
#[must_use]
pub fn map_error(err: &GateError, class: Class, policy: ExporterLossPolicy) -> Decision {
    if class.is_read_only() && policy == ExporterLossPolicy::Allow && is_degradable(err) {
        return Decision::allow(vec![ReasonCode::AllowPolicy], AuthClosure::new());
    }
    Decision::deny(reason_for(err))
}

/// Only loss of signing or of the exporter may ever degrade, and only for
/// `READ_ONLY`; every other error is a hard denial even for `READ_ONLY`.
#[must_use]
pub fn is_degradable(err: &GateError) -> bool {
    matches!(
        err,
        GateError::SignerUnavailable | GateError::ExporterUnavailable
    )
}

/// Convenience: deny with an explicit reason, used by engines that have already
/// classified the failure.
#[must_use]
pub fn deny(reason: ReasonCode) -> Decision {
    Decision::deny(reason)
}
