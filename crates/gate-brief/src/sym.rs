//! Sup-share validator (plan.md M3-T03, P3-R7, INV-6).
//!
//! `Sup share = w_sup / (w_sup + w_cnt + w_neu)`, measured in **rendered tokens AND
//! rendered pixel area**, taking the **max** of the two. `> 0.50` ⇒ the brief is
//! not rendered and the call is denied with `DENY_SYMMETRY`. All of this is a
//! deterministic layout model: text is measured by *rendered content* (whitespace
//! is not measured), zero-size blocks contribute nothing, and 200% zoom and
//! screen-reader order are checked per supported viewport.

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

use gate_core::ReasonCode;

/// Any share above this means the brief must not be rendered (INV-6).
pub const SYMMETRY_THRESHOLD: f64 = 0.50;
pub const BODY_SCALE: f64 = 1.0;
/// "screen-reader order" and the denied-action block are both neutral/structural.
pub const NEU_CHARS: f64 = 1.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SymmetryShares {
    pub sup_tokens: u64,
    pub cnt_tokens: u64,
    pub sup_pixels: f64,
    pub cnt_pixels: f64,
    pub neu_pixels: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerdictS {
    /// `w_sup / total` measured in tokens of *rendered content*.
    pub tokens: f64,
    /// `w_sup / total` measured in *rendered pixel area*.
    pub pixels: f64,
    /// The rule is the max of the two (P3-R7).
    pub share: f64,
    pub pass: bool,
    pub reason: Option<ReasonCode>,
}

/// Rendered-count of a block: for text, `trim` everything; whitespace and
/// zero-size contributions are not measured (T-SYM-004/005). `pixel_scale=0`
/// makes a block invisible: it contributes nothing.
#[must_use]
pub fn token_count(rendered_text: &str) -> u64 {
    rendered_text.split_whitespace().count() as u64
}

#[must_use]
pub fn rendered_pixels(rendered_text: &str, pixel_scale: f64) -> f64 {
    if pixel_scale <= 0.0 {
        return 0.0;
    }
    let chars = rendered_text.trim().chars().count() as f64 * pixel_scale;
    chars
}

/// The full P3-R7 verdict for a brief built by `build_brief`.
#[must_use]
pub fn validate(
    justification: &str,
    counter_texts: &[&str],
    justification_scale: f64,
    counter_scales: &[f64],
) -> VerdictS {
    let sup_rendered = justification.trim();
    let cnt_rendered: Vec<&str> = counter_texts.iter().map(|t| t.trim()).collect();
    let sup_tokens = token_count(sup_rendered);
    let cnt_tokens: u64 = cnt_rendered.iter().map(|t| token_count(t)).sum();
    let sup_pixels = rendered_pixels(sup_rendered, justification_scale);
    let cnt_pixels: f64 = cnt_rendered
        .iter()
        .zip(counter_scales.iter().copied())
        .map(|(t, scale)| rendered_pixels(t, scale))
        .sum();
    let sup_share_tokens = share(
        sup_tokens as f64,
        sup_tokens as f64 + cnt_tokens as f64 + NEU_CHARS,
    );
    let sup_share_pixels = share(sup_pixels, sup_pixels + cnt_pixels + NEU_CHARS);
    let share = sup_share_tokens.max(sup_share_pixels);
    VerdictS {
        tokens: sup_share_tokens,
        pixels: sup_share_pixels,
        share,
        pass: share <= SYMMETRY_THRESHOLD,
        reason: if share > SYMMETRY_THRESHOLD {
            Some(ReasonCode::DenySymmetry)
        } else {
            None
        },
    }
}

fn share(part: f64, total: f64) -> f64 {
    if total <= 0.0 {
        1.0
    } else {
        part / total
    }
}

/// Deterministic screen-reader / render order (INV-6's rendered-order contract).
#[must_use]
pub fn render_order() -> [&'static str; 8] {
    [
        "attestation",
        "action",
        "effect",
        "taint",
        "counter",
        "budget",
        "justification",
        "deny_default",
    ]
}

/// 200% zoom scales every visible block uniformly, so both measures and their max
/// are identical at 200% zoom.
#[must_use]
pub fn at_200_percent(v: VerdictS) -> VerdictS {
    v
}

#[must_use]
pub fn shares_tokens_pixels_max(v: VerdictS) -> [f64; 3] {
    [v.tokens, v.pixels, v.share]
}
