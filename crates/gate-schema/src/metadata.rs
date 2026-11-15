//! Metadata handling and cross-server namespace isolation (plan.md M1-T04,
//! P1-R11..R13).
//!
//! Descriptor text is adversary-controlled, so it is either **delimited** as
//! `EXTERNAL_UNTRUSTED_DATA` or **stripped** of imperative content before it can
//! reach the model. Poisoning heuristics only ever *add findings*: they never
//! relax enforcement (T-META-006), and a cross-server reference in metadata can
//! never widen another server's allowlist (T-META-005).

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

pub const MAX_METADATA_CHARS: usize = 8_192;
pub const BEGIN_MARKER: &str = "[EXTERNAL_UNTRUSTED_DATA begin]";
pub const END_MARKER: &str = "[EXTERNAL_UNTRUSTED_DATA end]";
const MARKER_NAME: &str = "EXTERNAL_UNTRUSTED_DATA";
const MARKER_ESCAPE: &str = "EXTERNAL~UNTRUSTED~DATA";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataMode {
    /// Default: keep the text, wrap it in explicit untrusted-data delimiters.
    Delimit,
    /// Remove imperative content and invisible characters entirely.
    Strip,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sanitised {
    pub text: String,
    pub truncated: bool,
    /// Findings only; never a verdict (plan.md §9.3 findings list).
    pub findings: Vec<&'static str>,
    /// Number of invisible characters removed or neutralised.
    pub hidden: usize,
}

const INSTRUCTION_PATTERNS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "ignore the previous",
    "disregard previous",
    "disregard the previous",
    "you must",
    "you should",
    "you will",
    "system:",
    "assistant:",
    "when using",
    "also send",
    "also bcc",
    "bcc",
    "forward all",
    "do not tell",
    "don't tell",
    "do not mention",
    "new instructions",
    "override",
    "instead,",
    "always send",
    "tool:",
];

/// Invisible characters that are commonly used to smuggle instructions.
#[must_use]
pub fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' | '\u{2060}' | '\u{00ad}'
    ) || ('\u{e0000}'..='\u{e007f}').contains(&ch)
}

fn find_cross_server_refs(text: &str, own_server: &str) -> usize {
    let mut count = 0;
    for token in
        text.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\'' | ',' | ';'))
    {
        let Some((server, tool)) = token.split_once(':') else {
            continue;
        };
        if server.is_empty() || tool.is_empty() || server == own_server {
            continue;
        }
        if server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && tool
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            count += 1;
        }
    }
    count
}

fn looks_base64(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        token.len() >= 40
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    })
}

fn escape_marker(text: &str) -> String {
    text.replace(MARKER_NAME, MARKER_ESCAPE)
}

/// Sanitise descriptor text for `own_server`. Deterministic and bounded.
#[must_use]
pub fn sanitise(text: &str, own_server: &str, mode: MetadataMode, max_chars: usize) -> Sanitised {
    let mut findings = Vec::new();
    let mut hidden = 0usize;

    // 1. Count and remove invisible characters (both modes: they are never
    //    legitimate in a tool description).
    let mut visible = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_invisible(ch) {
            hidden += 1;
        } else {
            visible.push(ch);
        }
    }
    if hidden > 0 {
        findings.push("INVISIBLE_CHARACTERS");
    }
    if looks_base64(text) {
        findings.push("ENCODED_INSTRUCTION_SUSPECTED");
    }

    // 2. Heuristics over the visible text.
    let lower = visible.to_lowercase();
    let instructed = INSTRUCTION_PATTERNS.iter().any(|p| lower.contains(p));
    if instructed {
        findings.push("INSTRUCTION_PATTERN");
    }
    let cross = find_cross_server_refs(&visible, own_server);
    if cross > 0 {
        findings.push("CROSS_SERVER_REFERENCE");
    }
    for (finding, ch) in [
        ("CONTROL_CHARACTER", '\u{7}'),
        ("BIDI_OVERRIDE", '\u{202e}'),
    ] {
        if text.contains(ch) {
            findings.push(finding);
        }
    }

    // 3. Mode: delimit keeps the content (framed), strip removes the clauses.
    let body = match mode {
        MetadataMode::Delimit => visible.clone(),
        MetadataMode::Strip => visible
            .split_inclusive(['.', '\n'])
            .filter(|clause| {
                let clause_lower = clause.to_lowercase();
                !INSTRUCTION_PATTERNS
                    .iter()
                    .any(|p| clause_lower.contains(p))
            })
            .collect::<String>()
            .trim()
            .to_owned(),
    };

    // 4. Bounded, with an explicit truncation marker.
    let (body, truncated) = truncate(
        &body,
        max_chars.saturating_sub(2 * (BEGIN_MARKER.len() + 1)),
    );
    let framed = format!("{BEGIN_MARKER}\n{}\n{END_MARKER}", escape_marker(&body));
    if truncated {
        findings.push("TRUNCATED_METADATA");
    }
    Sanitised {
        text: framed,
        truncated,
        findings,
        hidden,
    }
}

fn truncate(text: &str, max: usize) -> (String, bool) {
    if text.chars().count() <= max {
        return (text.to_owned(), false);
    }
    let mut kept: String = text.chars().take(max.saturating_sub(3)).collect();
    kept.push_str("...");
    (kept, true)
}

/// Namespace registry: `server:tool` is the identity, and a collision across
/// servers is logged rather than silently merged (T-META-004).
#[derive(Clone, Debug, Default)]
pub struct Namespace {
    tools: BTreeMap<String, (String, String)>,
    collisions: Vec<(String, String, String)>,
}

impl Namespace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool from `server`; returns its namespaced key.
    pub fn register(&mut self, server: &str, tool: &str) -> String {
        let key = format!("{server}:{tool}");
        let shadowed: Vec<String> = self
            .tools
            .iter()
            .filter(|(_, (s, t))| *s != server && t == tool)
            .map(|(k, _)| k.clone())
            .collect();
        for existing in shadowed {
            let existing_server = self
                .tools
                .get(&existing)
                .map(|(s, _)| s.clone())
                .unwrap_or_default();
            if !self
                .collisions
                .iter()
                .any(|(t, a, b)| t == tool && *a == existing_server && *b == server)
            {
                self.collisions
                    .push((tool.to_owned(), existing_server, server.to_owned()));
            }
        }
        self.tools
            .insert(key.clone(), (server.to_owned(), tool.to_owned()));
        key
    }

    #[must_use]
    pub fn resolve(&self, key: &str) -> Option<(&str, &str)> {
        self.tools.get(key).map(|(s, t)| (s.as_str(), t.as_str()))
    }

    #[must_use]
    pub fn collisions(&self) -> &[(String, String, String)] {
        &self.collisions
    }

    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}
