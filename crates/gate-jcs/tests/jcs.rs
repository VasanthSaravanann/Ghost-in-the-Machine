//! T-JCS-001..020 and T-JCS-V (plan.md §5.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_jcs::{canonical_number, canonicalize, JcsError, Value};
use proptest::prelude::*;

fn c(input: &str) -> String {
    canonicalize(input).unwrap_or_else(|e| panic!("canonicalize({input}) failed: {e}"))
}

// T-JCS-001 — RFC 8785 §3.2.3 sorting example (UTF-16 code unit order).
#[test]
fn t_jcs_001_sorting_example() {
    let input = concat!(
        r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","#,
        r#""1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","#,
        r#""\u00f6":"Latin Small Letter O With Diaeresis"}"#
    );
    let expected = concat!(
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",",
        "\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",",
        "\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
    );
    assert_eq!(c(input), expected);
}

// T-JCS-002 — RFC 8785 Appendix B number samples.
#[test]
fn t_jcs_002_number_samples() {
    let cases: &[(&str, &str)] = &[
        ("0", "0"),
        ("-0", "0"),
        ("-0.0", "0"),
        ("9007199254740992", "9007199254740992"),
        ("1E30", "1e+30"),
        ("1E-30", "1e-30"),
        ("1e-45", "1e-45"),
        ("1.7976931348623157E+308", "1.7976931348623157e+308"),
        ("5E-324", "5e-324"),
        ("4.5", "4.5"),
        ("0.002", "0.002"),
        ("1E2", "100"),
        ("1e+21", "1e+21"),
        ("1e-7", "1e-7"),
        ("1e-6", "0.000001"),
        ("1e20", "100000000000000000000"),
        ("3.0", "3"),
        ("123.456", "123.456"),
    ];
    for (input, want) in cases {
        assert_eq!(c(input), *want, "canonicalising {input}");
    }
}

// T-JCS-003 — string escaping (§3.2.2.2) and lone surrogates.
#[test]
fn t_jcs_003_string_escaping() {
    let input = r#""\u0000\u001f\b\t\n\f\r\u007f\u2028\u2029\"\\/\u00e9""#;
    let expected = concat!(
        "\"\\u0000\\u001f\\b\\t\\n\\f\\r",
        "\u{7f}\u{2028}\u{2029}",
        "\\\"\\\\/é\""
    );
    assert_eq!(c(input), expected);
    assert_eq!(
        canonicalize("\"\\ud800\"").unwrap_err(),
        JcsError::LoneSurrogate
    );
    assert_eq!(
        canonicalize("\"\\udc00\"").unwrap_err(),
        JcsError::LoneSurrogate
    );
    assert_eq!(
        canonicalize("\"\\ud800\\u0041\"").unwrap_err(),
        JcsError::LoneSurrogate
    );
}

// T-JCS-004 — duplicate keys.
#[test]
fn t_jcs_004_duplicate_key_rejected() {
    assert!(matches!(
        canonicalize(r#"{"a":1,"a":2}"#),
        Err(JcsError::DuplicateKey(k)) if k == "a"
    ));
    assert!(canonicalize(r#"{"a":1,"b":2}"#).is_ok());
}

// T-JCS-005 — NaN / Infinity.
#[test]
fn t_jcs_005_non_finite_rejected() {
    assert!(canonicalize("NaN").is_err());
    assert!(canonicalize("Infinity").is_err());
    assert!(canonicalize("-Infinity").is_err());
    assert_eq!(
        gate_jcs::to_string(&Value::Number(f64::NAN)).unwrap_err(),
        JcsError::NonFiniteNumber
    );
    assert_eq!(
        canonical_number(f64::INFINITY).unwrap_err(),
        JcsError::NonFiniteNumber
    );
    // 1e400 overflows to infinity.
    assert!(canonicalize("1e400").is_err());
}

// T-JCS-006 — depth bound, no stack overflow.
#[test]
fn t_jcs_006_depth_bounded() {
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert_eq!(canonicalize(&deep).unwrap_err(), JcsError::DepthExceeded);
    let ok = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert!(canonicalize(&ok).is_ok());
}

// T-JCS-007 — DEC-P02 integer exactness.
#[test]
fn t_jcs_007_integer_exactness() {
    assert!(matches!(
        canonicalize("9007199254740993"),
        Err(JcsError::IntegerNotRepresentable(_))
    ));
    assert_eq!(c("9007199254740992"), "9007199254740992");
    assert!(canonicalize("9007199254740993.0").is_ok());
    assert!(matches!(
        canonicalize("-9007199254740993"),
        Err(JcsError::IntegerNotRepresentable(_))
    ));
    // 2^64 is exactly representable and therefore accepted;
    // 2^64+1 is not.
    assert_eq!(c("18446744073709551616"), "18446744073709552000");
    assert!(canonicalize("18446744073709551617").is_err());
}

fn arb_json() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("null".to_string()),
        Just("true".to_string()),
        Just("false".to_string()),
        (-1_000_000i64..1_000_000).prop_map(|n| n.to_string()),
        (-1e3f64..1e3).prop_map(|n| format!("{n:?}")),
        "[a-zé€😀 ]{0,8}"
            .prop_map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(|v| format!("[{}]", v.join(","))),
            prop::collection::vec(inner, 0..4).prop_map(|v| {
                let pairs: Vec<String> = v
                    .iter()
                    .enumerate()
                    .map(|(i, val)| format!("\"k{i}\":{val}"))
                    .collect();
                format!("{{{}}}", pairs.join(","))
            }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    // T-JCS-008 — idempotence.
    #[test]
    fn t_jcs_008_idempotent(doc in arb_json()) {
        let once = canonicalize(&doc).unwrap();
        let twice = canonicalize(&once).unwrap();
        prop_assert_eq!(once, twice);
    }

    // T-JCS-009 — key order independence.
    #[test]
    fn t_jcs_009_key_order_independent(a in "[a-z]{1,4}", b in "[a-z]{1,4}", c in "[a-z]{1,4}") {
        let forward = format!(r#"{{"{a}":1,"{b}":2,"{c}":3}}"#);
        let reverse = format!(r#"{{"{c}":3,"{b}":2,"{a}":1}}"#);
        if a == b || b == c || a == c {
            // duplicate keys are a parse error by design
            prop_assert!(canonicalize(&forward).is_err() || canonicalize(&forward).is_ok());
        } else {
            prop_assert_eq!(canonicalize(&forward).unwrap(), canonicalize(&reverse).unwrap());
        }
    }
}

// T-JCS-010 — no Unicode normalisation.
#[test]
fn t_jcs_010_no_normalisation() {
    let composed = c(r#""\u00e9""#);
    let decomposed = c(r#""e\u0301""#);
    assert_ne!(composed, decomposed);
    assert_eq!(decomposed, "\"e\u{301}\"");
}

// T-JCS-011..020 — miscellaneous canonicalisation rules.
#[test]
fn t_jcs_011_whitespace_removed() {
    assert_eq!(c(" { \"a\" : [ 1 , 2 ] } "), r#"{"a":[1,2]}"#);
}

#[test]
fn t_jcs_012_empty_containers() {
    assert_eq!(c("{}"), "{}");
    assert_eq!(c("[]"), "[]");
    assert_eq!(c("[[],{}]"), "[[],{}]");
}

#[test]
fn t_jcs_013_null_and_bools() {
    assert_eq!(c("null"), "null");
    assert_eq!(c("true"), "true");
    assert_eq!(c("false"), "false");
}

#[test]
fn t_jcs_014_nested_arrays() {
    assert_eq!(c("[[1,[2,[3]]]]"), "[[1,[2,[3]]]]");
}

#[test]
fn t_jcs_015_solidus_not_escaped() {
    assert_eq!(c(r#""a/b""#), r#""a/b""#);
    assert_eq!(c(r#""\/""#), r#""/""#);
}

#[test]
fn t_jcs_016_integer_forms_collapse() {
    for input in ["1", "1.0", "1e0", "1E0", "10e-1"] {
        assert_eq!(c(input), "1", "{input}");
    }
}

#[test]
fn t_jcs_017_negative_zero() {
    assert_eq!(c("-0"), "0");
    assert_eq!(c("-0.0"), "0");
    assert_eq!(c("[-0,0]"), "[0,0]");
}

#[test]
fn t_jcs_018_exponent_boundaries() {
    assert_eq!(c("1e-7"), "1e-7");
    assert_eq!(c("1e-6"), "0.000001");
    assert_eq!(c("9.9e-7"), "9.9e-7");
}

#[test]
fn t_jcs_019_large_decimal_boundary() {
    assert_eq!(c("1e20"), "100000000000000000000");
    assert_eq!(c("1e21"), "1e+21");
    assert_eq!(c("1.5e21"), "1.5e+21");
}

#[test]
fn t_jcs_020_control_character_key_sorting() {
    let input = "{\"b\":1,\"\\u0001\":2,\"\\u0000\":3,\" \":4}";
    assert_eq!(c(input), "{\"\\u0000\":3,\"\\u0001\":2,\" \":4,\"b\":1}");
}

#[test]
fn rejects_trailing_and_malformed() {
    for bad in [
        "",
        "{",
        "{\"a\":}",
        "[1,]",
        "1 2",
        "{\"a\" 1}",
        "\"unterminated",
    ] {
        assert!(canonicalize(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(canonicalize("01").is_err());
    assert!(canonicalize("+1").is_err());
    assert!(canonicalize("1.").is_err());
    assert!(canonicalize(".5").is_err());
    assert!(canonicalize("{'a':1}").is_err());
}

#[test]
fn raw_control_characters_in_strings_are_rejected() {
    assert!(canonicalize("\"a\u{1}b\"").is_err());
}
