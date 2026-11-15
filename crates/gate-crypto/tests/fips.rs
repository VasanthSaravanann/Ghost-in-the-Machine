//! M6-T04 — FIPS profile: ECDSA-P256 + SHA-256 end to end, Ed25519 disabled.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::GateError;
use gate_crypto::{sha256_hex, KeyId, P256Signer, Signer, SuiteId, Verifier};
use gate_testkit::SeededRng;

#[test]
fn p256_and_sha256_work_in_this_profile() {
    let signer = P256Signer::generate(KeyId::new("p1"), &SeededRng::new(3)).unwrap();
    let sig = signer.sign(b"fips payload").unwrap();
    assert_eq!(sig.suite, SuiteId::P256Sha256);
    signer
        .verifying_key()
        .verify(b"fips payload", &sig)
        .unwrap();
    assert_eq!(
        sha256_hex(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[cfg(feature = "fips")]
#[test]
fn ed25519_is_refused_under_fips() {
    use gate_crypto::{Ed25519Signer, Signer};
    assert!(matches!(
        SuiteId::parse("ed25519"),
        Err(GateError::Unsupported(_))
    ));
    let signer = Ed25519Signer::from_seed(KeyId::new("k"), &[1u8; 32]);
    assert!(matches!(signer.sign(b"x"), Err(GateError::Unsupported(_))));
    let mut fake = signer.sign(b"x").unwrap_or_else(|_| {
        // Build a structurally valid signature to exercise the verifier path.
        gate_crypto::Signature {
            suite: SuiteId::Ed25519,
            key_id: KeyId::new("k"),
            bytes: vec![0u8; 64],
        }
    });
    fake.suite = SuiteId::Ed25519;
    assert!(matches!(
        signer.verifying_key().verify(b"x", &fake),
        Err(GateError::Unsupported(_))
    ));
}

#[cfg(not(feature = "fips"))]
#[test]
fn ed25519_is_available_outside_fips() {
    use gate_crypto::{Ed25519Signer, Signer};
    assert!(SuiteId::parse("ed25519").is_ok());
    let signer = Ed25519Signer::from_seed(KeyId::new("k"), &[1u8; 32]);
    assert!(signer.sign(b"x").is_ok());
}
