//! T-CRY-001..010 (plan.md §5.3).
//!
//! The Ed25519 known-answer suite is not applicable under the FIPS profile
//! (Ed25519 is disabled there); `tests/fips.rs` covers the FIPS surface.
#![cfg(not(feature = "fips"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::GateError;
use gate_crypto::{
    sha256_hex, Ed25519Signer, Ed25519Verifier, HsmKeyStore, KeyId, KeyStore, P256Signer,
    Signature, Signer, SoftKeyStore, SuiteId, Verifier,
};
use gate_testkit::SeededRng;

fn id(s: &str) -> KeyId {
    KeyId::new(s)
}

fn ed_signer(seed_byte: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(id("k1"), &[seed_byte; 32])
}

#[test]
fn t_cry_001_ed25519_roundtrip() {
    let signer = ed_signer(7);
    let sig = signer.sign(b"hello").unwrap();
    assert_eq!(sig.suite, SuiteId::Ed25519);
    let verifier = signer.verifying_key();
    verifier.verify(b"hello", &sig).unwrap();
}

#[test]
fn t_cry_002_bit_flip_rejected() {
    let signer = ed_signer(7);
    let verifier = signer.verifying_key();
    let sig = signer.sign(b"hello").unwrap();
    let mut tampered = sig.clone();
    tampered.bytes[0] ^= 0x01;
    assert_eq!(
        verifier.verify(b"hello", &tampered).unwrap_err(),
        GateError::VerificationFailed
    );
    assert_eq!(
        verifier.verify(b"hellp", &sig).unwrap_err(),
        GateError::VerificationFailed
    );
}

#[test]
fn t_cry_003_wrong_key_rejected() {
    let sig = ed_signer(7).sign(b"hello").unwrap();
    let other = ed_signer(9).verifying_key();
    assert_eq!(
        other.verify(b"hello", &sig).unwrap_err(),
        GateError::VerificationFailed
    );
    // Right bytes, wrong key id is also rejected.
    let mut mislabelled = sig.clone();
    mislabelled.key_id = id("someone-else");
    assert!(ed_signer(7)
        .verifying_key()
        .verify(b"hello", &mislabelled)
        .is_err());
}

#[test]
fn t_cry_004_p256_roundtrip_and_low_s() {
    let rng = SeededRng::new(5);
    let signer = P256Signer::generate(id("p1"), &rng).unwrap();
    let sig = signer.sign(b"hello").unwrap();
    assert_eq!(sig.suite, SuiteId::P256Sha256);
    assert_eq!(sig.bytes.len(), 64);
    signer.verifying_key().verify(b"hello", &sig).unwrap();

    // The produced signature is canonical (low-S).
    let parsed = p256::ecdsa::Signature::from_slice(&sig.bytes).unwrap();
    assert_eq!(parsed.normalize_s().to_bytes(), parsed.to_bytes());

    // A malleated high-S signature must be rejected.
    let high = parsed.normalize_s();
    let mut malleated = sig.clone();
    malleated.bytes = high.to_bytes().to_vec();
    if malleated.bytes != sig.bytes {
        assert_eq!(
            signer
                .verifying_key()
                .verify(b"hello", &malleated)
                .unwrap_err(),
            GateError::VerificationFailed
        );
    }

    // Tampering still fails.
    let mut tampered = sig.clone();
    tampered.bytes[3] ^= 0x80;
    assert!(signer.verifying_key().verify(b"hello", &tampered).is_err());
}

#[test]
fn t_cry_005_unknown_suite_rejected() {
    assert_eq!(
        SuiteId::parse("ed448").unwrap_err(),
        GateError::Unsupported("crypto suite \"ed448\"".into())
    );
    assert_eq!(SuiteId::parse("ed25519").unwrap(), SuiteId::Ed25519);
    // An Ed25519 signature presented as P-256 is rejected.
    let signer = ed_signer(7);
    let mut sig = signer.sign(b"x").unwrap();
    sig.suite = SuiteId::P256Sha256;
    assert!(signer.verifying_key().verify(b"x", &sig).is_err());
}

#[test]
fn t_cry_006_hsm_stub_is_unavailable() {
    let store = HsmKeyStore::new();
    assert_eq!(
        store.signer(&id("k")).err().unwrap(),
        GateError::SignerUnavailable
    );
    assert_eq!(
        store.verifier(&id("k")).err().unwrap(),
        GateError::SignerUnavailable
    );
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// RFC 8032 §7.1 TEST 1 (empty message). Vectors are copied from the RFC text;
/// they are cross-checked here by deriving the public key from the seed.
#[test]
fn t_cry_007_rfc8032_test1() {
    let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let want_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let want_sig = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    let signer = Ed25519Signer::from_seed(id("rfc1"), &seed);
    assert_eq!(hex::encode(signer.public_key()), want_pk);
    assert_eq!(hex::encode(signer.sign(b"").unwrap().bytes), want_sig);
}

/// RFC 8032 §7.1 TEST 2 (one-byte message 0x72).
#[test]
fn t_cry_008_rfc8032_test2() {
    let seed = hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let want_pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    let want_sig = concat!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    let signer = Ed25519Signer::from_seed(id("rfc2"), &seed);
    assert_eq!(hex::encode(signer.public_key()), want_pk);
    assert_eq!(hex::encode(signer.sign(&[0x72]).unwrap().bytes), want_sig);
}

/// Ed25519 is deterministic: signing twice yields identical bytes (R6).
#[test]
fn t_cry_009_signature_deterministic() {
    let signer = ed_signer(11);
    let a = signer.sign(b"same message").unwrap();
    let b = signer.sign(b"same message").unwrap();
    assert_eq!(a.bytes, b.bytes);
}

/// SHA-256 known answer (empty input, NIST FIPS 180-4).
#[test]
fn t_cry_010_sha256_known_answer() {
    assert_eq!(
        sha256_hex(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn soft_keystore_roundtrips_both_suites() {
    let mut store = SoftKeyStore::new();
    store.insert_ed25519(Ed25519Signer::from_seed(id("e"), &[3u8; 32]));
    store.insert_p256(P256Signer::generate(id("p"), &SeededRng::new(1)).unwrap());

    for key in ["e", "p"] {
        let signer = store.signer(&id(key)).unwrap();
        let verifier = store.verifier(&id(key)).unwrap();
        let sig = signer.sign(b"payload").unwrap();
        verifier.verify(b"payload", &sig).unwrap();
        assert!(store.signer(&id("missing")).is_err());
    }
}

#[test]
fn signature_serialises_with_suite_and_key() {
    let sig = ed_signer(1).sign(b"x").unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    assert!(json.contains("\"suite\":\"ed25519\""));
    assert!(json.contains("\"key_id\":\"k1\""));
    let back: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sig);
    assert!(serde_json::from_str::<Signature>(
        "{\"suite\":\"ed448\",\"key_id\":\"k\",\"bytes\":[]}"
    )
    .is_err());
}

#[test]
fn verifier_constructors_validate_key_material() {
    assert!(Ed25519Verifier::from_public_bytes(id("k"), &[0u8; 31]).is_err());
    assert!(P256Signer::from_secret_bytes(id("k"), &[0u8; 31]).is_err());
    assert!(P256Signer::from_secret_bytes(id("k"), &[0u8; 32]).is_err());
}
