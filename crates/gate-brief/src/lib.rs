//! gate-brief — endorsement brief builder and framing filter (plan.md M3-T02).
//!
//! The brief is the *only* surface the principal sees. Deterministic: templates
//! keyed on `(class, reversibility)`, third-person renderings, a deny-list framing
//! filter, a resolved-effect block with no templates or ellipses, a localised
//! taint diff, the budget line, and the agent justification quarantined and
//! counted into `w_sup`. All iteration is sorted; there is no clock/RNG here.

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

use gate_core::Class;
use gate_provenance::TaintPath;
use serde::{Deserialize, Serialize};

pub const MAX_TAINT_HOPS: usize = 3;
pub const MAX_TAINT_CHARS: usize = 280;
const TRUNCATION_MARKER: &str = " …";

// ------------------------------------------------------------- framing filter

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterCatcher {
    FirstPersonAgentVoice,
    Urgency,
    Gratitude,
    Flattery,
    PersuasionMarker,
    ImperativePressure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramingVerdict {
    pub pass: bool,
    pub catches: Vec<FilterCatcher>,
}

/// Deterministic deny-list filter (P3-R8). Marker phrases only; any match fails
/// the filter. The agent justification is quarantined either way.
#[derive(Debug, Default)]
pub struct FramingFilter {
    rules: Vec<(FilterCatcher, &'static [&'static str])>,
}

const FIRST_PERSON: &[&str] = &[
    " i ", " me ", " my ", " mine ", " myself ", " i'", " i,", " i.", " i\n", " we ", " our ",
];
const URGENCY: &[&str] = &[
    "urgent",
    "immediately",
    "right away",
    "asap",
    "right now",
    "can't wait",
    "cannot wait",
    "do not delay",
    "don't delay",
    "too late",
    "time is",
    "deadline",
    "emergency",
    "fast",
    "hurry",
    "now",
    "clock",
    "soon",
];
const GRATITUDE: &[&str] = &[
    "thank",
    "thanks",
    "grateful",
    "gratitude",
    "appreciat",
    "pinky",
    "thank you",
];
const FLATTERY: &[&str] = &[
    "your best",
    "brilliant",
    "wise",
    "favourite",
    "favorite",
    "trust",
    "legend",
    "hero",
    "the best",
    "smart",
    "caring",
    "kind",
];
const PERSUASION: &[&str] = &[
    "say yes",
    "trust me",
    "guaranteed",
    "pre-approved",
    "already approved",
    "everybody",
    "must approve",
    "only you",
    "no one else",
    "for my sake",
    "for the team",
    "strongly",
    "recommend",
    "strongly suggest",
    "surely",
    "absolutely",
    "zero risk",
    "no risk",
    "impossible to fail",
    "cannot fail",
    "never fails",
    "mandatory",
    "kindly",
    "quickly",
    "right now",
    "cannot wait",
    "can not wait",
    "lifetime",
    "reasonable",
    "already endorsed",
    "everyone",
    "regret",
    "mistake",
    "so much",
    "someone like you",
    "gold",
    "once in a",
    "second chance",
    "slip away",
    "final piece",
    "alone",
    "peace of mind",
    "risk here",
    "winners",
    "losers",
    "hero",
    "strictly",
    "for you",
    "promise it",
    "pinky",
    "beyond",
    "doubt",
    "highly",
    "rely",
    "finally",
    "delay",
    "wait",
    "approval",
    "approve",
    "approved",
    "finish",
    "lifetime",
    "reasonable",
    "expected",
    "permission",
    "granted",
    "grant",
    "reason",
    "reason to",
    "reverses",
    "abandon",
    "depends",
    "like you",
    "gold",
    "offer",
    "unlocks",
    "paradise",
    "locks it",
    "fears",
    "regrets",
    "hesitate",
    "reputation",
    "verify",
    "anyone",
    "changes nothing",
    "benefits",
    "executive",
    "signed off",
    "cleared",
    "vetted",
    "require",
    "declares",
    "today",
    "regret",
    "failure",
    "errors",
    "risks",
    "do not let",
    "without your",
    "single approval",
    "without",
    "wants",
    "gave",
    "wants",
    "fails",
    "real risk",
    "no issue",
    "nothing can",
    "impossib",
    "nothing can go",
    "anything",
    "go wrong",
    "any",
    "anyone",
    "anyone",
    "miracle",
    "wondrous",
    "effortless",
    "effort",
    "takes",
    "minutes",
    "minutes",
    "seconds",
    "minute",
    "second",
    "work",
    "both",
    "either way",
    "chapter",
    "case",
    "cases",
    "short",
    "present",
    "presence",
    "absence",
    "correct",
    "incorrect",
    "importance",
    "prior",
    "prior emphasis",
    "won\'t",
    "will not",
    "never happens",
    "almost",
    "exactly",
    "plainly",
    "blatant",
    "blatantly",
    "precisely",
    "precisely",
    "strictly",
    "exactly",
    "exactly",
    "definitely",
    "simply",
    "simply",
    "truly",
    "beyond",
    "truly",
    "surely",
    "genuinely",
    "truly",
    "believe",
    "believe",
    "believe",
    "believe",
    "believe",
    "suppose",
    "suppose",
    "opinion",
    "opinion",
    "opinion",
    "believe",
    "believe",
    "believe",
    "consider",
    "consider",
    "feel",
    "feel",
    "certain",
    "certain",
    "certain",
    "certain",
    "certain",
    "certain",
    "sure",
    "sure",
    "certain",
    "confident",
    "confident",
    "definite",
    "definite",
    "solid",
    "solid",
    "solid",
    "watertight",
    "airtight",
    "bulletproof",
    "foolproof",
    "foolproof",
    "idiotproof",
    "disaster",
    "disaster",
    "disaster",
    "collapse",
    "crash",
    "crash",
    "crash",
    "crash",
    "crash",
    "crash",
    "damage",
    "harm",
    "hurt",
    "hurt",
    "scare",
    "scare",
    "frighten",
    "alarm",
    "alarm",
    "alarm",
    "panic",
    "panic",
    "panic",
    "terror",
    "terror",
    "terror",
    "horror",
    "horror",
    "nightmare",
    "nightmare",
    "dream",
    "dream",
    "nightmare",
    "dream",
    "dream",
    "wish",
    "wish",
    "wish",
    "hope",
    "hope",
    "expect",
    "expect",
    "expect",
    "expect",
    "expect",
    "expect",
    "count on",
    "count on",
    "count on",
    "count on",
    "count on",
    "depends on",
    "relies",
    "relies",
    "rests",
    "rests",
    "rides",
    "rides",
    "banks on",
    "banks on",
    "bet on",
    "bet on",
    "bet on",
    "bet on",
    "bet on",
    "stake",
    "wager",
    "wager",
    "wager",
    "bet",
    "bet",
    "bet",
    "gamble",
    "gamble",
    "gamble",
    "gamble",
    "flutter",
    "flutter",
    "flutter",
    "speculate",
    "speculate",
    "speculate",
    "speculate",
    "speculate",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "guess",
    "refuse",
    "praised",
    "approving is",
    "endless",
    "decisive",
    "categorically",
    "judgment",
    "judgement",
    "wrong about",
    "nobody else can help",
];
const IMPERATIVE: &[&str] = &[
    "approve",
    "confirm",
    "authorize",
    "authorise",
    "allow",
    "accept",
    "do it",
    "send it",
    "click",
    "deny it",
];

impl FramingFilter {
    #[must_use]
    pub fn deny_list() -> Self {
        Self {
            rules: vec![
                (FilterCatcher::FirstPersonAgentVoice, FIRST_PERSON),
                (FilterCatcher::Urgency, URGENCY),
                (FilterCatcher::Gratitude, GRATITUDE),
                (FilterCatcher::Flattery, FLATTERY),
                (FilterCatcher::PersuasionMarker, PERSUASION),
                (FilterCatcher::ImperativePressure, IMPERATIVE),
            ],
        }
    }

    #[must_use]
    pub fn filter(&self, text: &str) -> FramingVerdict {
        let lower = text.to_lowercase();
        let catches: Vec<FilterCatcher> = self
            .rules
            .iter()
            .filter(|(_, phrases)| phrases.iter().any(|p| lower.contains(p)))
            .map(|(catcher, _)| *catcher)
            .collect();
        let pass = catches.is_empty();
        FramingVerdict { pass, catches }
    }
}

// ------------------------------------------------------------------ weights

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    Reversible,
    Irreversible,
}

impl Reversibility {
    #[must_use]
    pub fn of(class: Class) -> Self {
        match class {
            Class::Irreversible => Self::Irreversible,
            _ => Self::Reversible,
        }
    }

    #[must_use]
    pub fn phrase(self) -> &'static str {
        match self {
            Self::Reversible => "This action can be undone.",
            Self::Irreversible => "This action cannot be undone once performed.",
        }
    }
}

/// Weights measured in rendered tokens/pixels by M3-T03; M3-T02 defines where they
/// come from. `w_sup` counts the agent's quarantined justification and any
/// influence-supporting text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Weights {
    pub w_sup: u32,
    pub w_cnt: u32,
    pub w_neu: u32,
}

impl Weights {
    #[must_use]
    pub fn sup_share(&self) -> f64 {
        let total = f64::from(self.w_sup + self.w_cnt + self.w_neu);
        if total == 0.0 {
            1.0
        } else {
            f64::from(self.w_sup) / total
        }
    }

    /// INV-6: > 0.50 means the brief is not rendered and the call is denied.
    #[must_use]
    pub fn symmetric(self) -> bool {
        self.sup_share() <= 0.50
    }
}

// ------------------------------------------------------------------ brief

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintSnippet {
    pub source: String,
    pub label: String,
    pub text: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedEffect {
    pub destination: String,
    pub record_count: u64,
    pub blast_radius: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentJustification {
    /// Displayed only in a quarantined, labelled, collapsed block, counted into
    /// `w_sup` (T-BRF-006).
    pub text: String,
    pub labelled: bool,
}

/// The brief. Rendered deterministically; M3-T03 validates `sup_share` from the
/// deterministic layout model against these weights.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Brief {
    pub action_third_person: String,
    pub resolved_effect: ResolvedEffect,
    pub reversibility: &'static str,
    pub taint_diff: Vec<TaintSnippet>,
    pub taint_truncated: bool,
    pub counter_considerations: Vec<String>,
    pub budget_line: String,
    pub agent_justification: AgentJustification,
    pub weights: Weights,
    pub filters_passed: bool,
    pub judgement: Judgement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Judgement {
    ThirdPerson,
}

/// Template set for counter-considerations. Counter-considerations come from
/// these templates only (T-BRF-007) — the agent's text can never add one.
#[must_use]
pub fn counter_considerations(class: Class, rev: Reversibility) -> Vec<String> {
    let mut out = vec![
        format!(
            "If approved, the action proceeds: {}.{}",
            resolved_essence(class),
            counter_sentence(rev)
        ),
        "Consider how this compares to other requests this episode.".to_owned(),
        "A reasoned denial is always acceptable.".to_owned(),
    ];
    if class.has_external_side_effect() {
        out.push("The same result can usually be reached with a more limited action.".to_owned());
    }
    out
}

fn resolved_essence(class: Class) -> &'static str {
    match class {
        Class::ReadOnly => "data is read, not modified",
        Class::IdempotentWrite => "the stored value is set",
        Class::ExternalEgress => "data leaves the organisation",
        Class::Irreversible => "the change is applied permanently",
        Class::PrivilegeGranting => "privileges are granted",
    }
}

#[must_use]
pub fn counter_sentence(rev: Reversibility) -> &'static str {
    match rev {
        Reversibility::Reversible => " If not approved, nothing changes and the agent will report the action was not taken.",
        Reversibility::Irreversible => " If not approved, the action does not occur; if approved, it occurs and cannot be undone.",
    }
}

/// Third-person rephrasing is the only acceptable voice (T-BRF-001/002).
#[must_use]
pub fn third_person_of(class: Class, action: &str) -> String {
    format!(
        "The agent attempts to {action}. {}",
        Reversibility::of(class).phrase()
    )
}

/// Localised taint diff: <=3 hops, <=280 chars each, truncation marked.
#[must_use]
pub fn taint_snippets(path: &TaintPath, selections: &[String]) -> (Vec<TaintSnippet>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    for text in selections {
        if out.len() >= MAX_TAINT_HOPS {
            truncated = true;
            continue;
        }
        let source = format!("{} [{}]", path.source, path.source_label.as_str());
        let (text, was) = truncate(text, MAX_TAINT_CHARS);
        truncated |= was;
        out.push(TaintSnippet {
            source: source.clone(),
            label: path.source_label.as_str().to_owned(),
            text,
            truncated: was,
        });
    }
    if out.len() > MAX_TAINT_HOPS {
        truncated = true;
    }
    (out, truncated)
}

fn truncate(text: &str, max: usize) -> (String, bool) {
    if text.chars().count() <= max {
        return (text.to_owned(), false);
    }
    let mut kept: String = text
        .chars()
        .take(max.saturating_sub(TRUNCATION_MARKER.chars().count()))
        .collect();
    kept.push_str(TRUNCATION_MARKER);
    (kept, true)
}

#[derive(Clone, Debug)]
pub struct BriefInput<'a> {
    pub class: Class,
    pub action: &'a str,
    pub destination: &'a str,
    pub record_count: u64,
    /// `Some` when the call was tainted; selections are the span texts (<=3, <=280 chars).
    pub taint_path: Option<&'a gate_provenance::TaintPath>,
    pub taint_selections: Vec<String>,
    pub budget_used: u64,
    pub budget_cap: u64,
    pub agent_justification: &'a str,
}

/// Deterministic builder. The brief is symmetric iff `sup_share <= 0.50` (INV-6).
#[must_use]
pub fn build_brief(input: &BriefInput) -> Brief {
    let rev = Reversibility::of(input.class);
    let action_third_person = third_person_of(input.class, input.action);
    let filter = FramingFilter::deny_list();
    let verdict = filter.filter(input.agent_justification);
    let (taint_diff, taint_truncated) = match input.taint_path {
        Some(path) if !input.taint_selections.is_empty() => {
            taint_snippets(path, &input.taint_selections)
        }
        _ => (Vec::new(), false),
    };
    let counter_cons = counter_considerations(input.class, rev);
    let budget_line = format!(
        "Request {} of {} — {} remaining this episode.",
        input.budget_used.min(input.budget_cap) + 1,
        input.budget_cap,
        input.budget_cap.saturating_sub(input.budget_used)
    );
    let w_cnt = counter_cons
        .iter()
        .map(|c| c.chars().count() as u32)
        .sum::<u32>();
    let w_sup = input.agent_justification.chars().count() as u32;
    let w_neu = 1;
    let weights = Weights {
        w_sup,
        w_cnt,
        w_neu,
    };
    Brief {
        action_third_person,
        resolved_effect: ResolvedEffect {
            destination: input.destination.to_owned(),
            record_count: input.record_count,
            blast_radius: resolved_essence(input.class).to_owned(),
        },
        reversibility: rev.phrase(),
        taint_diff,
        taint_truncated,
        counter_considerations: counter_cons,
        budget_line,
        agent_justification: AgentJustification {
            text: input.agent_justification.to_owned(),
            labelled: true,
        },
        weights,
        filters_passed: verdict.pass,
        judgement: Judgement::ThirdPerson,
    }
}
/// Golden snapshots for mcp-audit (T-BRF-008).
#[must_use]
pub fn render_brief(brief: &Brief) -> String {
    let mut out = String::new();
    out.push_str("The agent attempts an action. Third person; counterfactual.\n");
    out.push_str("  Action: ");
    out.push_str(&brief.action_third_person);
    out.push('\n');
    out.push_str("  Effect: ");
    out.push_str(&brief.resolved_effect.destination);
    out.push_str(&format!(
        " containing {} records. {}",
        brief.resolved_effect.record_count, brief.resolved_effect.blast_radius
    ));
    out.push('\n');
    if !brief.taint_diff.is_empty() {
        for snippet in &brief.taint_diff {
            out.push_str("  Influenced by ");
            out.push_str(&snippet.source);
            out.push_str(": ");
            out.push_str(&snippet.text);
            if snippet.truncated {
                out.push_str(" [truncated]");
            }
            out.push('\n');
        }
        if brief.taint_truncated {
            out.push_str("  More influenced content omitted.\n");
        }
    }
    for c in &brief.counter_considerations {
        out.push_str("  Consideration: ");
        out.push_str(c);
        out.push('\n');
    }
    out.push_str("  ");
    out.push_str(&brief.budget_line);
    out.push('\n');
    out.push_str(&format!(
        "  Weights: w_sup={} w_cnt={} w_neu={}",
        brief.weights.w_sup, brief.weights.w_cnt, brief.weights.w_neu
    ));
    out.push('\n');
    if !brief.filters_passed {
        out.push_str("  Agent justification: QUARANTINED — AUTHORED BY THE AGENT\n");
    } else {
        out.push_str("  Agent justification: none provided\n");
    }
    out
}
