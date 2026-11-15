//! T-JCS-V — differential test against the independent implementation in
//! `ref/jcs_ref.py` over 100,000 generated documents (plan.md §5.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

/// Deterministic xorshift64* — the corpus must be reproducible (R6).
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let i = (self.next() % items.len() as u64) as usize;
        &items[i]
    }

    fn range(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const NUMBERS: &[&str] = &[
    "0",
    "-0",
    "1",
    "2",
    "42",
    "-17",
    "1000000",
    "9007199254740992",
    "1e20",
    "1e21",
    "1e-7",
    "1e-6",
    "4.5",
    "0.002",
    "1.5e-7",
    "123.456",
    "-3.25",
    "1e30",
    "1e-30",
    "2.2250738585072014e-308",
    "1.7976931348623157e308",
    "5e-324",
    "0.1",
    "0.2",
    "1e-45",
];

const STRINGS: &[&str] = &[
    "",
    "plain",
    "with \"quote\"",
    "back\\slash",
    "tab\there",
    "line\nbreak",
    "\u{1}control",
    "\u{7f}del",
    "\u{2028}ls\u{2029}ps",
    "café",
    "e\u{301}",
    "€uro",
    "😀 emoji",
    "דּ",
    "zero\u{200b}width",
    "a/b",
    "/",
];

fn string_literal(g: &mut Gen) -> String {
    let s = g.pick(STRINGS);
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn value(g: &mut Gen, depth: u32) -> String {
    match g.range(if depth == 0 { 3 } else { 5 }) {
        0 => "null".to_string(),
        1 => {
            if g.range(2) == 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        2 => g.pick(NUMBERS).to_string(),
        3 => string_literal(g),
        4 => {
            let n = g.range(4);
            let items: Vec<String> = (0..n).map(|_| value(g, depth - 1)).collect();
            format!("[{}]", items.join(","))
        }
        _ => {
            let n = g.range(4);
            let items: Vec<String> = (0..n)
                .map(|i| format!("\"k{i}\":{}", value(g, depth - 1)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[test]
fn t_jcs_v_differential_100k() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let ref_impl = root.join("ref/jcs_ref.py");
    assert!(ref_impl.exists(), "reference implementation missing");

    let mut g = Gen(0x5DEE_CE66_D000_0001);
    let mut corpus = String::new();
    for _ in 0..100_000 {
        let doc = value(&mut g, 3);
        let canonical = gate_jcs::canonicalize(&doc)
            .unwrap_or_else(|e| panic!("generated document rejected: {doc} ({e})"));
        // The canonical form must itself re-canonicalise identically.
        assert_eq!(gate_jcs::canonicalize(&canonical).unwrap(), canonical);
        let _ = writeln!(
            corpus,
            "{{\"in\":\"{}\",\"out\":\"{}\"}}",
            json_escape(&doc),
            json_escape(&canonical)
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corpus.jsonl");
    std::fs::write(&path, corpus).unwrap();

    let out = Command::new("python3")
        .arg(&ref_impl)
        .arg(&path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "differential mismatch:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("100000 documents, 0 mismatches"),
        "{stdout}"
    );
}
