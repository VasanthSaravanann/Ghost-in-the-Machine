//! Budget and rate limits for endorsements (plan.md M3-T01, P3-R1..R6, INV-7).
//!
//! INV-7: escalations per episode ≤ `E_max`, and the cap can never be raised
//! in-band. Raising or resetting a cap is a distinct ledger entry that only an
//! out-of-band principal action can create; every other path that *requests* a
//! raise is ignored and logged. Deterministic: injected clock, `BTreeMap`
//! iteration, no RNG.

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
use std::fmt;

use gate_core::{Class, PrincipalId, ReasonCode};

pub const DEFAULT_ESCALATION_CAP: u64 = 5;
/// Minimum spacing between prompts (P3-R4).
pub const MIN_INTER_PROMPT_MS: i64 = 20_000;

/// A principal action is the only way a cap can change (P3-R3). In M3 the
/// endorsement channel produces these; no other caller may.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapAction {
    Raise { to: u64 },
    RaiseEndorsement { by: u64 },
    Reset { to: u64 },
    SetDeltaT { dt_ms: i64 },
}

pub trait PrincipalGate: Send + Sync {
    /// `None` means the request is not from the out-of-band principal channel.
    fn approve_cap_action(&self) -> Option<PrincipalId>;
}

#[derive(Debug, Default)]
pub struct NoPrincipal;

impl PrincipalGate for NoPrincipal {
    fn approve_cap_action(&self) -> Option<PrincipalId> {
        None
    }
}

impl<T: PrincipalGate> PrincipalGate for std::sync::Arc<T> {
    fn approve_cap_action(&self) -> Option<PrincipalId> {
        self.as_ref().approve_cap_action()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetEvent {
    pub at_ms: i64,
    pub class: Class,
    pub kind: BudgetEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetEventKind {
    /// An endorsement prompt was *rendered* and consumed budget (DEC-P03).
    PromptRendered,
    /// The queue overflowed: denied with APPROVAL_SPAM_SUSPECTED.
    QueueOverflow,
    /// An in-band cap-raise request was ignored and logged (T-BUD-002).
    InBandRaiseIgnored { requested: u64 },
    /// A cap change approved out-of-band, recordable as a distinct ledger entry.
    CapChanged { action: CapAction, by: PrincipalId },
    /// A similar-request cooldown suppressed a prompt (T-BUD-006).
    CooldownSuppressed { similar_to: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    CapExhausted,
    TooSoon { wait_ms: i64 },
    QueueFull,
    NotAuthorised,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExhausted => write!(f, "endorsement cap exhausted for this episode/class"),
            Self::TooSoon { wait_ms } => {
                write!(f, "prompt too soon; wait {wait_ms} ms (rate limit)")
            }
            Self::QueueFull => write!(f, "approval queue full (spam suspected)"),
            Self::NotAuthorised => {
                write!(f, "cap change is not authorised by the principal channel")
            }
        }
    }
}

/// A queued prompt (DEC-P03): rendered no earlier than the rate-limit window and
/// consuming budget only when rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedPrompt {
    pub slot: u64,
    pub class: Class,
    pub eligible_at_ms: i64,
    pub hash: u64,
}

/// Per-episode budget with a hard, non-raiseable-in-band cap (INV-7).
#[derive(Clone, Debug)]
pub struct BudgetTracker {
    episode: String,
    /// used <= cap is the invariant; enforced at every mutation and by
    /// `remaining()`.
    used: BTreeMap<Class, u64>,
    cap: BTreeMap<Class, u64>,
    last_prompt_ms: BTreeMap<Class, i64>,
    last_hash_prompted: BTreeMap<(Class, u64), i64>,
    queue: Vec<QueuedPrompt>,
    events: Vec<BudgetEvent>,
    next_slot: u64,
    cooldown_ms: i64,
    max_queue: usize,
}

#[derive(Clone, Debug)]
pub struct BudgetView {
    pub used: u64,
    pub cap: u64,
    /// `remaining() == cap - used`, always non-negative by construction.
    pub remaining: u64,
}

impl BudgetTracker {
    #[must_use]
    pub fn new(episode: impl Into<String>, max_queue: usize, cooldown_ms: i64) -> Self {
        let mut cap = BTreeMap::new();
        for class in CLASSES {
            cap.insert(class, DEFAULT_ESCALATION_CAP);
        }
        Self {
            episode: episode.into(),
            used: BTreeMap::new(),
            cap,
            last_prompt_ms: BTreeMap::new(),
            last_hash_prompted: BTreeMap::new(),
            queue: Vec::new(),
            events: Vec::new(),
            next_slot: 0,
            cooldown_ms,
            max_queue,
        }
    }

    #[must_use]
    pub fn episode(&self) -> &str {
        &self.episode
    }

    #[must_use]
    pub fn cap(&self, class: Class) -> u64 {
        self.cap
            .get(&class)
            .copied()
            .unwrap_or(DEFAULT_ESCALATION_CAP)
    }

    /// The invariant, everywhere: `used <= cap`.
    #[must_use]
    pub fn used(&self, class: Class) -> u64 {
        self.used.get(&class).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn remaining(&self, class: Class) -> u64 {
        self.cap(class).saturating_sub(self.used(class))
    }

    #[must_use]
    pub fn view(&self, class: Class) -> BudgetView {
        let used = self.used(class);
        let cap = self.cap(class);
        BudgetView {
            used,
            cap,
            remaining: cap.saturating_sub(used),
        }
    }

    /// Enqueue a prompt request. The render happens later via
    /// [`BudgetTracker::render_next`]; budget is consumed only at render.
    pub fn request_prompt(
        &mut self,
        class: Class,
        now_ms: i64,
        hash: u64,
    ) -> Result<u64, BudgetError> {
        if self.queue.len() >= self.max_queue {
            self.events.push(BudgetEvent {
                at_ms: now_ms,
                class,
                kind: BudgetEventKind::QueueOverflow,
            });
            return Err(BudgetError::QueueFull);
        }
        // Rate limit: a burst is queued, never rendered immediately.
        let eligible = self
            .last_prompt_ms
            .get(&class)
            .map(|last| last + MIN_INTER_PROMPT_MS)
            .unwrap_or(now_ms)
            .max(now_ms);
        // Similar-request cooldown: near-identical requests consume budget
        // without a re-prompt within cooldown_ms (T-BUD-006). The bump is
        // clamped by the cap so `used <= cap` is never violated (INV-7).
        if let Some(previous) = self.last_hash_prompted.get(&(class, hash)) {
            if *previous <= now_ms && now_ms - *previous <= self.cooldown_ms {
                if self.used(class) < self.cap(class) {
                    self.used.entry(class).and_modify(|u| *u += 1).or_insert(1);
                    self.events.push(BudgetEvent {
                        at_ms: now_ms,
                        class,
                        kind: BudgetEventKind::CooldownSuppressed {
                            similar_to: *previous as u64,
                        },
                    });
                }
                return Err(BudgetError::TooSoon { wait_ms: 0 });
            }
        }
        if self.used(class) >= self.cap(class) {
            return Err(BudgetError::CapExhausted);
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        let wait = (eligible - now_ms).max(0);
        if wait > 0 {
            self.queue.push(QueuedPrompt {
                slot,
                class,
                eligible_at_ms: eligible,
                hash,
            });
            Ok(slot)
        } else {
            // Rendering immediately is allowed (and consumes budget now).
            self.render_lock(class, eligible, hash);
            self.events.push(BudgetEvent {
                at_ms: now_ms,
                class,
                kind: BudgetEventKind::PromptRendered,
            });
            Ok(slot)
        }
    }

    fn render_lock(&mut self, class: Class, at_ms: i64, hash: u64) {
        self.used.entry(class).and_modify(|u| *u += 1).or_insert(1);
        if let Some(at) = self.last_prompt_ms.get_mut(&class) {
            *at = at_ms;
        } else {
            self.last_prompt_ms.insert(class, at_ms);
        }
        self.last_hash_prompted.insert((class, hash), at_ms);
    }

    /// Render every prompt whose eligibility window has passed. Budget is
    /// consumed only here (DEC-P03).
    pub fn render_due(&mut self, now_ms: i64) -> Vec<QueuedPrompt> {
        let mut due: Vec<QueuedPrompt> = self
            .queue
            .iter()
            .filter(|q| q.eligible_at_ms <= now_ms)
            .cloned()
            .collect();
        // Render in order, stopping the moment budget is exhausted, so used<=cap
        // holds after every call (INV-7).
        let mut rendered: Vec<QueuedPrompt> = Vec::new();
        for prompt in due.drain(..) {
            if self.used(prompt.class) >= self.cap(prompt.class) {
                break;
            }
            self.render_lock(prompt.class, prompt.eligible_at_ms, prompt.hash);
            rendered.push(prompt);
        }
        for prompt in &rendered {
            self.events.push(BudgetEvent {
                at_ms: now_ms,
                class: prompt.class,
                kind: BudgetEventKind::PromptRendered,
            });
        }
        self.queue
            .retain(|q| !rendered.iter().any(|d| d.slot == q.slot));
        rendered
    }

    /// An in-band cap-raise request (from a tool result, descriptor, or model
    /// text) is ignored and logged; the cap never moves (T-BUD-002, ADV-INV7).
    pub fn request_in_band_raise(&mut self, class: Class, to: u64, now_ms: i64) {
        self.events.push(BudgetEvent {
            at_ms: now_ms,
            class,
            kind: BudgetEventKind::InBandRaiseIgnored { requested: to },
        });
    }

    /// The only cap path: an out-of-band principal approval, recorded as a
    /// distinct ledger entry (T-BUD-003).
    pub fn approve_cap_change(
        &mut self,
        principal: &dyn PrincipalGate,
        class: Class,
        action: CapAction,
        now_ms: i64,
    ) -> Result<(), BudgetError> {
        let by = principal
            .approve_cap_action()
            .ok_or(BudgetError::NotAuthorised)?;
        let new_cap = match action {
            CapAction::Raise { to } => to.clamp(1, 100),
            CapAction::RaiseEndorsement { by } => self.cap(class).saturating_add(by).clamp(1, 100),
            CapAction::Reset { to } => to.clamp(1, 100),
            CapAction::SetDeltaT { .. } => self.cap(class),
        };
        let used = self.used(class).min(new_cap);
        self.cap.insert(class, new_cap);
        *self.used.entry(class).or_insert(used) = used;
        self.events.push(BudgetEvent {
            at_ms: now_ms,
            class,
            kind: BudgetEventKind::CapChanged { action, by },
        });
        Ok(())
    }

    /// All events in order (deterministic) — these become ledger entries.
    #[must_use]
    pub fn events(&self) -> &[BudgetEvent] {
        &self.events
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.iter().all(|(_, u)| *u == 0) && self.queue.is_empty()
    }

    /// INV-7 in one query: for every class, `used <= cap`.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        Class::ALL
            .iter()
            .all(|class| self.used(*class) <= self.cap(*class))
    }
}

pub const CLASSES: [Class; 5] = Class::ALL;

// ------------------------------------------------------------------ engine

/// Budget-aware decision decoration (used by mcp-gate). Kept tiny: the tracker
/// is the source of truth; `decide_budget` only maps the tracker's state into
/// the closed reason-code set.
#[must_use]
pub fn decide_budget(used: u64, cap: u64) -> Option<ReasonCode> {
    if used >= cap {
        Some(ReasonCode::DenyBudget)
    } else {
        None
    }
}

/// Tiny alias used by the engine decoration and tests.
#[must_use]
pub fn in_cap(used: u64, cap: u64) -> Option<ReasonCode> {
    decide_budget(used, cap)
}
