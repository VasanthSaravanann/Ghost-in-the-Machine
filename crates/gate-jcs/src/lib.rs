//! gate-jcs — RFC 8785 JSON Canonicalisation Scheme (plan.md §2.4, §5.2).
//!
//! Deliberate divergences from a permissive JSON parser, all required by the
//! spec:
//! * duplicate object keys are rejected (T-JCS-004);
//! * lone surrogates are rejected (T-JCS-003);
//! * integer literals that are not exactly representable as an IEEE 754 double
//!   are rejected (DEC-P02 / T-JCS-007) so two distinct inputs can never
//!   canonicalise to the same bytes;
//! * nesting depth is bounded (T-JCS-006).

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

use std::cmp::Ordering;
use std::fmt;

/// Maximum nesting depth. Deeply nested adversary input must fail bounded, not
/// overflow the stack (T-JCS-006).
pub const MAX_DEPTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// The input is not valid JSON.
    Syntax {
        offset: usize,
        message: &'static str,
    },
    /// An object repeats a key (RFC 8785 §3.1, T-JCS-004).
    DuplicateKey(String),
    /// A `\uD800`-style escape is not part of a well-formed pair (T-JCS-003).
    LoneSurrogate,
    /// NaN, ±Infinity and overflowed literals are not JSON (T-JCS-005).
    NonFiniteNumber,
    /// An integer literal cannot round-trip through an IEEE 754 double
    /// (DEC-P02, T-JCS-007).
    IntegerNotRepresentable(String),
    /// Nesting exceeded [`MAX_DEPTH`].
    DepthExceeded,
    /// Trailing non-whitespace after the top-level value.
    TrailingCharacters,
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { offset, message } => {
                write!(f, "JSON syntax error at byte {offset}: {message}")
            }
            Self::DuplicateKey(k) => write!(f, "duplicate object key: {k:?}"),
            Self::LoneSurrogate => f.write_str("lone surrogate in string"),
            Self::NonFiniteNumber => f.write_str("non-finite number"),
            Self::IntegerNotRepresentable(s) => {
                write!(f, "integer literal not exactly representable as f64: {s}")
            }
            Self::DepthExceeded => write!(f, "nesting exceeds {MAX_DEPTH}"),
            Self::TrailingCharacters => f.write_str("trailing characters after JSON value"),
        }
    }
}

impl std::error::Error for JcsError {}

/// A parsed JSON value. Objects keep insertion order here; canonical ordering is
/// applied at serialisation.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    #[must_use]
    pub fn object(pairs: Vec<(impl Into<String>, Value)>) -> Self {
        Self::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

/// Parse then canonicalise (RFC 8785 §3.2.1–§3.2.3).
pub fn canonicalize(input: &str) -> Result<String, JcsError> {
    let value = parse(input)?;
    to_string(&value)
}

/// Canonical serialisation of an already-parsed value.
pub fn to_string(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&canonical_number(*n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(pairs) => {
            let mut sorted: Vec<&(String, Value)> = pairs.iter().collect();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            let mut previous: Option<&str> = None;
            for (i, (key, val)) in sorted.iter().enumerate() {
                if let Some(prev) = previous {
                    if prev == key.as_str() {
                        return Err(JcsError::DuplicateKey(key.clone()));
                    }
                }
                previous = Some(key.as_str());
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.3: sort by UTF-16 code units, not by code point or UTF-8 bytes.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// ECMA-262 §7.1.12.1 number serialisation, as mandated by RFC 8785 §3.2.2.3.
pub fn canonical_number(value: f64) -> Result<String, JcsError> {
    if !value.is_finite() {
        return Err(JcsError::NonFiniteNumber);
    }
    // Covers both +0.0 and -0.0 (§3.2.2.3 step 1).
    if value == 0.0 {
        return Ok("0".to_owned());
    }
    // Rust's `{:e}` yields the shortest round-tripping digits, e.g. "1.5e-7".
    let shortest = format!("{value:e}");
    let (mantissa, exponent) = shortest.split_once('e').ok_or(JcsError::NonFiniteNumber)?;
    let exponent: i32 = exponent.parse().map_err(|_| JcsError::Syntax {
        offset: 0,
        message: "bad exponent",
    })?;
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa
        .trim_start_matches('-')
        .chars()
        .filter(|c| *c != '.')
        .collect();
    let k = i32::try_from(digits.len()).map_err(|_| JcsError::NonFiniteNumber)?;
    let n = exponent + 1;

    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        push_zeros(&mut out, (n - k) as usize);
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        out.push_str(slice(&digits, 0, split)?);
        out.push('.');
        out.push_str(slice(&digits, split, digits.len())?);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        push_zeros(&mut out, (-n) as usize);
        out.push_str(&digits);
    } else {
        out.push_str(slice(&digits, 0, 1)?);
        if k > 1 {
            out.push('.');
            out.push_str(slice(&digits, 1, digits.len())?);
        }
        out.push('e');
        let e = n - 1;
        out.push(if e >= 0 { '+' } else { '-' });
        out.push_str(&e.abs().to_string());
    }
    Ok(out)
}

fn push_zeros(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push('0');
    }
}

fn slice(s: &str, from: usize, to: usize) -> Result<&str, JcsError> {
    s.get(from..to).ok_or(JcsError::Syntax {
        offset: from,
        message: "slice out of range",
    })
}

/// RFC 8785 §3.2.2.2 string escaping. Only the seven short escapes plus
/// `\u00xx` for the remaining C0 controls; nothing else is escaped
/// (U+007F and U+2028 are emitted literally).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                out.push(hex_digit((c as u32) >> 4));
                out.push(hex_digit(c as u32 & 0x0f));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex_digit(nibble: u32) -> char {
    match nibble {
        0..=9 => char::from(b'0' + u8::try_from(nibble).unwrap_or(0)),
        _ => char::from(b'a' + u8::try_from(nibble - 10).unwrap_or(0)),
    }
}

/// Recursive-descent parser with an explicit depth bound.
pub fn parse(input: &str) -> Result<Value, JcsError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let value = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(JcsError::TrailingCharacters);
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, message: &'static str) -> JcsError {
        JcsError::Syntax {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, want: u8) -> Result<(), JcsError> {
        if self.peek() == Some(want) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err("unexpected byte"))
        }
    }

    fn parse_value(&mut self) -> Result<Value, JcsError> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err("unexpected byte")),
            None => Err(JcsError::Syntax {
                offset: self.pos,
                message: "unexpected end of input",
            }),
        }
    }

    fn literal(&mut self, text: &[u8], value: Value) -> Result<Value, JcsError> {
        let end = self.pos.saturating_add(text.len());
        if self.bytes.get(self.pos..end) == Some(text) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn enter(&mut self) -> Result<(), JcsError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JcsError::DepthExceeded);
        }
        Ok(())
    }

    fn parse_array(&mut self) -> Result<Value, JcsError> {
        self.expect(b'[')?;
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn parse_object(&mut self) -> Result<Value, JcsError> {
        self.expect(b'{')?;
        self.enter()?;
        let mut pairs: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Object(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            if pairs.iter().any(|(existing, _)| *existing == key) {
                return Err(JcsError::DuplicateKey(key));
            }
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
        self.depth -= 1;
        Ok(Value::Object(pairs))
    }

    fn parse_string(&mut self) -> Result<String, JcsError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            if self.pos > start {
                // The input is a &str, so non-ASCII bytes are valid UTF-8.
                out.push_str(self.slice_str(start, self.pos)?);
            }
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.parse_escape(&mut out)?;
                }
                Some(_) => return Err(self.err("raw control character in string")),
                None => {
                    return Err(JcsError::Syntax {
                        offset: self.pos,
                        message: "unterminated string",
                    });
                }
            }
        }
    }

    fn slice_str(&self, from: usize, to: usize) -> Result<&'a str, JcsError> {
        std::str::from_utf8(self.bytes.get(from..to).unwrap_or_default())
            .map_err(|_| self.err("invalid UTF-8"))
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), JcsError> {
        let c = self.bump().ok_or_else(|| self.err("unterminated escape"))?;
        let simple = match c {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{08}'),
            b'f' => Some('\u{0c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            b'u' => None,
            _ => return Err(self.err("invalid escape")),
        };
        if let Some(ch) = simple {
            out.push(ch);
            return Ok(());
        }
        let first = self.parse_hex4()?;
        let ch = match first {
            0xD800..=0xDBFF => {
                // High surrogate: a low surrogate must follow.
                if self.bump() != Some(b'\\') {
                    return Err(JcsError::LoneSurrogate);
                }
                if self.bump() != Some(b'u') {
                    return Err(JcsError::LoneSurrogate);
                }
                let second = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(JcsError::LoneSurrogate);
                }
                let combined = 0x1_0000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                char::from_u32(combined).ok_or(JcsError::LoneSurrogate)?
            }
            0xDC00..=0xDFFF => return Err(JcsError::LoneSurrogate),
            other => char::from_u32(other).ok_or(JcsError::LoneSurrogate)?,
        };
        out.push(ch);
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u32, JcsError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| self.err("short \\u escape"))?;
            let d = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a') + 10,
                b'A'..=b'F' => u32::from(b - b'A') + 10,
                _ => return Err(self.err("invalid \\u escape")),
            };
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Value, JcsError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        let mut is_integer_literal = true;
        if self.peek() == Some(b'.') {
            is_integer_literal = false;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_integer_literal = false;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let literal = self.slice_str(start, self.pos)?;
        if is_integer_literal && !integer_exact_as_double(literal) {
            return Err(JcsError::IntegerNotRepresentable(literal.to_owned()));
        }
        let value: f64 = literal.parse().map_err(|_| self.err("invalid number"))?;
        if !value.is_finite() {
            return Err(JcsError::NonFiniteNumber);
        }
        Ok(Value::Number(value))
    }
}

/// DEC-P02: an integer literal must survive a round trip through f64.
fn integer_exact_as_double(literal: &str) -> bool {
    let digits = literal.trim_start_matches('-');
    if digits.is_empty() || digits.len() > 39 {
        return false;
    }
    if let Ok(magnitude) = digits.parse::<u128>() {
        let as_double = magnitude as f64;
        return as_double.is_finite() && as_double as u128 == magnitude;
    }
    false
}
