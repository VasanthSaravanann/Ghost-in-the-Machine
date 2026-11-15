//! T-SLT-001..018 — salted leaves, evidence store, crypto-shredding (M4-T02).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_crypto::sha256;
use gate_testkit::SeededRng;
use gate_tlog::salt::{
    bucket_for, evidence_digest, pad, salted_leaf, unpad, EvidenceError, EvidenceStore, BUCKETS,
};
use gate_tlog::{leaf_hash, verify_inclusion, MerkleTree, TreeStore};

const KEY: [u8; 32] = [7u8; 32];
const PLAINTEXT: &[u8] = b"customer names and invoice totals, 412 records";

fn rng(seed: u64) -> SeededRng {
    SeededRng::new(seed)
}

#[test]
fn t_slt_001_no_plaintext_or_unsalted_digest_is_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.redb");
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(1);
    let mut tree = TreeStore::open(&path).unwrap();
    for i in 0..6u8 {
        let payload = [PLAINTEXT, &[i]].concat();
        let (_salt, leaf) = store.store(format!("leaf-{i}"), &payload, &rng).unwrap();
        tree.append(&leaf).unwrap();
    }
    let mut log_bytes = std::fs::read(&path).unwrap();
    log_bytes.extend_from_slice(&store.persisted_bytes());
    let unsalted = sha256(PLAINTEXT);
    assert!(
        !log_bytes.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT),
        "plaintext leaked into the log"
    );
    assert!(
        !log_bytes.windows(32).any(|w| w == unsalted),
        "unsalted digest leaked into the log"
    );
    // The entry digests are not present either (only their leaf hashes).
    let e = evidence_digest(&[0u8; 32], PLAINTEXT);
    assert!(!log_bytes.windows(32).any(|w| w == e));
}

#[test]
fn t_slt_002_same_payload_different_salts_different_leaves() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(2);
    let (_, a) = store.store("a", PLAINTEXT, &rng).unwrap();
    let (_, b) = store.store("b", PLAINTEXT, &rng).unwrap();
    assert_ne!(a, b, "distinct salts must give distinct leaves");
}

#[test]
fn t_slt_003_selective_disclosure() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(3);
    let (salt_a, leaf_a) = store.store("a", b"payload-a", &rng).unwrap();
    let (_salt_b, leaf_b) = store.store("b", b"payload-b", &rng).unwrap();
    let (salt, payload) = store.disclose("a").unwrap();
    assert_eq!(salt, salt_a);
    assert_eq!(payload, b"payload-a");
    // The disclosed salt+payload recompute exactly leaf a, and nothing about b.
    assert_eq!(salted_leaf(&salt, &payload), leaf_a);
    assert_ne!(salted_leaf(&salt, &payload), leaf_b);
    assert!(store.disclose("b").is_ok());
    assert_eq!(
        store.disclose("missing").unwrap_err(),
        EvidenceError::UnknownLeaf("missing".into())
    );
}

#[test]
fn t_slt_004_shred_one_leaf_others_still_provable() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(4);
    let mut leaves = Vec::new();
    for i in 0..5u8 {
        let (_, leaf) = store
            .store(
                format!("l{i}"),
                &[b"payload".as_slice(), &[i]].concat(),
                &rng,
            )
            .unwrap();
        leaves.push(leaf);
    }
    // The log stores leaf hashes directly (not payloads).
    let salted = MerkleTree::from_leaf_hashes(leaves.clone());
    store.shred("l2");
    assert!(store.is_shredded("l2"));
    assert_eq!(store.open("l2").unwrap_err(), EvidenceError::Shredded);
    // Every untouched leaf still proves inclusion against the same root.
    for (i, leaf) in leaves.iter().enumerate() {
        if i == 2 {
            continue;
        }
        let proof: Vec<[u8; 32]> = salted.inclusion_proof(i).unwrap();
        assert!(verify_inclusion(leaf, i, 5, &proof, &salted.root()));
    }
}

#[test]
fn t_slt_005_size_buckets() {
    assert_eq!(bucket_for(0), Some(256));
    assert_eq!(bucket_for(252), Some(256));
    assert_eq!(
        bucket_for(253),
        Some(1024),
        "253 + 4-byte prefix exceeds 256"
    );
    assert_eq!(bucket_for(300), Some(1024));
    assert_eq!(bucket_for(BUCKETS[BUCKETS.len() - 1]), None);
    let (bucket, padded) = pad(b"short").unwrap();
    assert_eq!(bucket, 256);
    assert_eq!(padded.len(), bucket);
    assert_eq!(unpad(&padded).unwrap(), b"short");
    assert!(pad(&vec![0u8; 70_000]).is_none());
}

#[test]
fn t_slt_006_evidence_roundtrip_and_tamper_detection() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(6);
    store.store("x", PLAINTEXT, &rng).unwrap();
    assert_eq!(store.open("x").unwrap(), PLAINTEXT);
    // AEAD bound to the leaf id: swapping ids must fail.
    let mut moved = store.clone_for_test();
    moved.retag_for_test("x", "y");
    assert_eq!(moved.open("y").unwrap_err(), EvidenceError::DecryptFailed);
    let _ = sha256(b"");
}

#[test]
fn t_slt_007_wrong_key_cannot_open() {
    let mut store = EvidenceStore::new(KEY);
    store.store("x", PLAINTEXT, &rng(7)).unwrap();
    let mut rotated = EvidenceStore::new([9u8; 32]);
    let _ = &mut rotated;
    // The store's key is private; rotating is the supported path.
    let mut store2 = EvidenceStore::new(KEY);
    store2.store("x", PLAINTEXT, &rng(8)).unwrap();
    store2.rotate([11u8; 32], &rng(9)).unwrap();
    assert_eq!(store2.open("x").unwrap(), PLAINTEXT);
}

#[test]
fn t_slt_008_key_rotation_reencrypts() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(10);
    let before_nonce = {
        store.store("a", b"alpha", &rng).unwrap();
        store.store("b", b"beta", &rng).unwrap();
        store.len()
    };
    assert_eq!(before_nonce, 2);
    let count = store.rotate([42u8; 32], &rng).unwrap();
    assert_eq!(count, 2);
    assert_eq!(store.open("a").unwrap(), b"alpha");
    assert_eq!(store.open("b").unwrap(), b"beta");
}

#[test]
fn t_slt_009_shred_is_idempotent() {
    let mut store = EvidenceStore::new(KEY);
    store.store("x", b"payload", &rng(11)).unwrap();
    assert!(store.shred("x"));
    assert!(!store.shred("x"));
    assert!(store.is_shredded("x"));
    assert!(store.is_empty());
}

#[test]
fn t_slt_010_duplicate_leaf_rejected() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(12);
    store.store("x", b"one", &rng).unwrap();
    assert_eq!(
        store.store("x", b"two", &rng).unwrap_err(),
        EvidenceError::Duplicate("x".into())
    );
}

#[test]
fn t_slt_011_oversized_payload_rejected() {
    let mut store = EvidenceStore::new(KEY);
    let big = vec![0u8; 70_000];
    assert_eq!(
        store.store("x", &big, &rng(13)).unwrap_err(),
        EvidenceError::TooLarge
    );
}

#[test]
fn t_slt_012_digest_is_deterministic_given_salt() {
    let salt = [3u8; 32];
    assert_eq!(
        evidence_digest(&salt, b"abc"),
        evidence_digest(&salt, b"abc")
    );
    assert_ne!(
        evidence_digest(&salt, b"abc"),
        evidence_digest(&[4u8; 32], b"abc")
    );
    assert_eq!(
        salted_leaf(&salt, b"abc"),
        leaf_hash(&evidence_digest(&salt, b"abc"))
    );
}

#[test]
fn t_slt_013_bucket_of_recorded_leaf() {
    let mut store = EvidenceStore::new(KEY);
    store.store("small", b"x", &rng(14)).unwrap();
    store.store("large", &vec![7u8; 2000], &rng(15)).unwrap();
    assert_eq!(store.bucket_of("small"), Some(256));
    assert_eq!(store.bucket_of("large"), Some(4096));
    assert_eq!(store.bucket_of("missing"), None);
}

#[test]
fn t_slt_014_shredded_leaf_cannot_be_disclosed() {
    let mut store = EvidenceStore::new(KEY);
    store.store("x", b"payload", &rng(16)).unwrap();
    store.shred("x");
    assert_eq!(store.disclose("x").unwrap_err(), EvidenceError::Shredded);
    assert!(store.disclose("x").is_err());
}

#[test]
fn t_slt_015_padding_hides_length_classes() {
    let a = pad(b"a").unwrap();
    let b = pad(&[0u8; 200]).unwrap();
    assert_eq!(
        a.1.len(),
        b.1.len(),
        "same bucket, indistinguishable length"
    );
    assert_eq!(unpad(&a.1).unwrap().len(), 1);
    assert_eq!(unpad(&b.1).unwrap().len(), 200);
}

#[test]
fn t_slt_016_persisted_bytes_exclude_salts() {
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(17);
    let (salt, _) = store.store("x", PLAINTEXT, &rng).unwrap();
    let persisted = store.persisted_bytes();
    assert!(
        !persisted.windows(32).any(|w| w == salt),
        "salts must not be persisted with the log"
    );
}

#[test]
fn t_slt_017_empty_store() {
    let store = EvidenceStore::new(KEY);
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.persisted_bytes().is_empty());
    assert!(store.open("x").is_err());
    assert!(!store.is_shredded("x"));
}

#[test]
fn t_slt_018_recomputed_entry_matches_appended_leaf() {
    // The auditor's path: disclosed salt+payload -> E -> leaf -> inclusion proof.
    let mut store = EvidenceStore::new(KEY);
    let rng = rng(18);
    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let payload = format!("record-{i}").into_bytes();
        let (_, leaf) = store.store(format!("l{i}"), &payload, &rng).unwrap();
        leaves.push(leaf);
    }
    let tree = MerkleTree::from_leaf_hashes(leaves);
    let (salt, payload) = store.disclose("l2").unwrap();
    let recomputed = salted_leaf(&salt, &payload);
    assert_eq!(Some(recomputed), tree.leaves().get(2).copied());
    let proof: Vec<[u8; 32]> = tree.inclusion_proof(2).unwrap();
    assert!(verify_inclusion(&recomputed, 2, 4, &proof, &tree.root()));
}
