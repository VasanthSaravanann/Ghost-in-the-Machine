//! gate-ledger — budget/rate limits, endorsement ledger (plan.md §2.1, M3).
//! M3-T04 adds the split-leaf ledger; M3-T01 ships the budget side.

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

pub mod budget;
pub mod drift;
pub mod leaf;

pub use budget::{
    BudgetError, BudgetEvent, BudgetEventKind, BudgetTracker, BudgetView, CapAction, PrincipalGate,
};
pub use drift::{
    combine, second_principal_brief, DecisionRecord, DriftMetrics, DualOutcome,
    DualPrincipalRequest, FirstPrincipalInput, PrincipalMetrics, Tightening, REGRET_THRESHOLD,
    RUBBER_STAMP_MS, WINDOW,
};
pub use leaf::{
    EndorsementLedger, FramingSummary, LeafA, LeafB, LedgerError, ReleaseReceipt, Resume,
    SignedLeafA, Stage,
};
