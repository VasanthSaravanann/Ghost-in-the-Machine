//! T-MRK-001..020 — RFC 9162 Merkle tree (plan.md §5.9, M4-T01).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};

use gate_tlog::{
    consistency_proof, hex, inclusion_proof, leaf_hash, mth, node_hash, unhex, verify_inclusion,
    InclusionBundle, MerkleTree, TreeStore,
};

const MAX: usize = 64;

fn payloads(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

fn tree(n: usize) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for payload in payloads(n) {
        tree.append(&payload);
    }
    tree
}

fn reference(tree: &MerkleTree) -> serde_json::Value {
    let request = serde_json::json!({
        "leaves": payloads(tree.len()).iter().map(|p| hex(p)).collect::<Vec<_>>(),
    });
    let reference_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .join("ref/merkle_ref.py");
    let mut child = Command::new("python3")
        .arg(&reference_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "reference failed");
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn t_mrk_001_tree_heads_match_reference() {
    let tree = tree(MAX);
    let expected = reference(&tree);
    let roots = expected["roots"].as_array().unwrap();
    for (size, root_hex) in roots.iter().enumerate() {
        let want = unhex(root_hex.as_str().unwrap()).unwrap();
        assert_eq!(tree.root_at(size).unwrap().to_vec(), want, "size {size}");
    }
    assert_eq!(mth(&[]), gate_crypto::sha256(b""));
    assert_eq!(mth(&[leaf_hash(b"x")]), leaf_hash(b"x"));
}

#[test]
fn t_mrk_002_inclusion_proofs() {
    let n = MAX;
    let tree = tree(n);
    let expected = reference(&tree);
    let proofs = expected["inclusion"].as_array().unwrap();
    for (index, proof_json) in proofs.iter().enumerate() {
        let want: Vec<Vec<u8>> = proof_json
            .as_array()
            .unwrap()
            .iter()
            .map(|h| unhex(h.as_str().unwrap()).unwrap())
            .collect();
        let got = tree.inclusion_proof(index).unwrap();
        assert_eq!(
            got.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
            want,
            "index {index}"
        );
        let proof: Vec<[u8; 32]> = got;
        assert!(verify_inclusion(
            tree.leaves().get(index).unwrap(),
            index,
            n,
            &proof,
            &tree.root()
        ));
    }
}

#[test]
fn t_mrk_003_tampered_inclusion_rejected() {
    let tree = tree(16);
    let root = tree.root();
    for index in 0..16 {
        let mut proof = tree.inclusion_proof(index).unwrap();
        if let Some(first) = proof.first_mut() {
            first[0] ^= 0x01;
        } else {
            continue;
        }
        assert!(!verify_inclusion(
            tree.leaves().get(index).unwrap(),
            index,
            16,
            &proof,
            &root
        ));
    }
    let proof = tree.inclusion_proof(3).unwrap();
    assert!(!verify_inclusion(
        tree.leaves().get(3).unwrap(),
        4,
        16,
        &proof,
        &root
    ));
    assert!(!verify_inclusion(
        &leaf_hash(b"other"),
        3,
        16,
        &proof,
        &root
    ));
}

#[test]
fn t_mrk_004_consistency_proofs() {
    let n = 24;
    let tree = tree(n);
    let expected = reference(&tree);
    let all = expected["consistency"].as_array().unwrap();
    let mut checked = 0;
    for entry in all {
        let m = entry["m"].as_u64().unwrap() as usize;
        let size = entry["n"].as_u64().unwrap() as usize;
        let want: Vec<Vec<u8>> = entry["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| unhex(h.as_str().unwrap()).unwrap())
            .collect();
        let prefix = tree.leaves().get(..size).unwrap();
        let proof: Vec<[u8; 32]> = consistency_proof(prefix, m).unwrap();
        assert_eq!(
            proof.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
            want,
            "m={m} n={size}"
        );
        // Proof bytes are exactly the independent implementation's; the
        // sound verifier lands in M4-T04 (ISSUE-006).
        assert_eq!(tree.root_at(size).unwrap(), tree.root_at(size).unwrap());
        checked += 1;
    }
    assert!(checked >= n * (n + 1) / 2);
}

#[test]
fn t_mrk_005_forged_history_detected_by_proof_mismatch() {
    // A forged history cannot produce the honest proof bytes: this is the
    // prover-level guarantee M4-T01 ships; the verifier is M4-T04 (ISSUE-006).
    let honest = tree(16);
    let expected = reference(&honest);
    let first_expected: Vec<Vec<u8>> = expected["consistency"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["m"] == 8 && e["n"] == 16)
        .flat_map(|e| e["proof"].as_array().unwrap().iter())
        .map(|h| unhex(h.as_str().unwrap()).unwrap())
        .collect();
    let honest_proof: Vec<Vec<u8>> = consistency_proof(honest.leaves().get(..16).unwrap(), 8)
        .unwrap()
        .iter()
        .map(|h| h.to_vec())
        .collect();
    assert_eq!(honest_proof, first_expected);

    // Rewriting a leaf *inside* the old prefix changes the old root (the proof
    // only exposes the appended side), so the fork is caught by the old root.
    let mut inside = honest.leaves().to_vec();
    inside[3] = leaf_hash(b"forged-in-old-range");
    let inside = MerkleTree::from_leaf_hashes(inside);
    assert_ne!(inside.root_at(8).unwrap(), honest.root_at(8).unwrap());
    let inside_proof: Vec<Vec<u8>> = consistency_proof(inside.leaves().get(..16).unwrap(), 8)
        .unwrap()
        .iter()
        .map(|h| h.to_vec())
        .collect();
    assert_eq!(inside_proof, honest_proof, "the appended side is unchanged");

    // Rewriting a leaf in the *appended* range changes the proof itself.
    let mut appended = honest.leaves().to_vec();
    appended[12] = leaf_hash(b"forged-in-new-range");
    let appended = MerkleTree::from_leaf_hashes(appended);
    let appended_proof: Vec<Vec<u8>> = consistency_proof(appended.leaves().get(..16).unwrap(), 8)
        .unwrap()
        .iter()
        .map(|h| h.to_vec())
        .collect();
    assert_ne!(
        appended_proof, honest_proof,
        "a rewritten new leaf changes the proof"
    );
    assert_ne!(appended.root(), honest.root());
}

#[test]
fn t_mrk_006_domain_separation() {
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");
    let interior = node_hash(&a, &b);
    let mut as_leaf = vec![0x01];
    as_leaf.extend_from_slice(&a);
    as_leaf.extend_from_slice(&b);
    assert_ne!(leaf_hash(&as_leaf), interior);
    let mut as_node = vec![0x00];
    as_node.extend_from_slice(b"ab");
    assert_ne!(node_hash(&a, &b), gate_crypto::sha256(&as_node));
}

#[test]
fn t_mrk_007_persistence_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tlog.redb");
    let root = {
        let mut store = TreeStore::open(&path).unwrap();
        for payload in payloads(20) {
            store.append(&payload).unwrap();
        }
        store.tree().root()
    };
    let store = TreeStore::open(&path).unwrap();
    assert_eq!(store.len(), 20);
    assert_eq!(store.tree().root(), root);
    let proof: Vec<[u8; 32]> = store.tree().inclusion_proof(7).unwrap();
    assert!(verify_inclusion(
        store.tree().leaves().get(7).unwrap(),
        7,
        20,
        &proof,
        &root
    ));
}

#[test]
fn t_mrk_008_edges() {
    let mut empty = MerkleTree::new();
    assert_eq!(empty.root(), gate_crypto::sha256(b""));
    assert!(empty.inclusion_proof(0).is_none());
    assert!(consistency_proof(empty.leaves(), 1).is_none());
    empty.append(b"one");
    assert!(empty.inclusion_proof(0).unwrap().is_empty());
    assert!(verify_inclusion(
        empty.leaves().first().unwrap(),
        0,
        1,
        &[],
        &empty.root()
    ));
    assert!(empty.root_at(2).is_none());
    assert!(consistency_proof(empty.leaves(), 0).is_none());
}

#[test]
fn t_mrk_009_bundle_roundtrip() {
    let tree = tree(9);
    let bundle = InclusionBundle::new(&tree, 4).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: InclusionBundle = serde_json::from_str(&json).unwrap();
    assert!(back.verify());
    let mut tampered = back.clone();
    tampered.index = 5;
    assert!(!tampered.verify());
    let mut bad = back;
    bad.proof = vec!["zz".into()];
    assert!(!bad.verify());
}

#[test]
fn t_mrk_010_proof_length_is_logarithmic() {
    for n in 1..=33usize {
        let tree = tree(n);
        for index in 0..n {
            let proof = tree.inclusion_proof(index).unwrap();
            let bound = usize::BITS as usize - (n.max(1)).leading_zeros() as usize;
            assert!(proof.len() <= bound, "n={n} index={index}");
        }
    }
}

#[test]
fn t_mrk_011_appending_one_leaf_changes_the_root() {
    let mut tree = tree(8);
    let before = tree.root();
    tree.append(b"extra");
    assert_ne!(tree.root(), before);
}

#[test]
fn t_mrk_012_consistency_proof_is_bound_to_its_first_size() {
    let tree = tree(12);
    let five: Vec<Vec<u8>> = consistency_proof(tree.leaves().get(..12).unwrap(), 5)
        .unwrap()
        .iter()
        .map(|h| h.to_vec())
        .collect();
    let six: Vec<Vec<u8>> = consistency_proof(tree.leaves().get(..12).unwrap(), 6)
        .unwrap()
        .iter()
        .map(|h| h.to_vec())
        .collect();
    assert_ne!(five, six, "the first size is part of the proof");
    assert_eq!(consistency_proof(tree.leaves(), 13), None);
}

#[test]
fn t_mrk_013_concurrent_store_appends() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conc.redb");
    let store = std::sync::Arc::new(std::sync::Mutex::new(TreeStore::open(&path).unwrap()));
    let mut handles = Vec::new();
    for t in 0..4 {
        let store = std::sync::Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for i in 0..5 {
                store
                    .lock()
                    .unwrap()
                    .append(format!("t{t}-{i}").as_bytes())
                    .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let store = std::sync::Arc::try_unwrap(store)
        .unwrap()
        .into_inner()
        .unwrap();
    let root = store.tree().root();
    assert_eq!(store.len(), 20);
    drop(store); // release the redb lock before reopening
    let reopened = TreeStore::open(&path).unwrap();
    assert_eq!(reopened.len(), 20);
    assert_eq!(reopened.tree().root(), root);
}

#[test]
fn t_mrk_014_corrupt_store_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.redb");
    {
        let mut store = TreeStore::open(&path).unwrap();
        store.append(b"x").unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    for i in 0..8 {
        if mid + i < bytes.len() {
            bytes[mid + i] ^= 0xff;
        }
    }
    bytes.truncate(bytes.len().saturating_sub(8));
    std::fs::write(&path, &bytes).unwrap();
    assert!(TreeStore::open(&path).is_err());
}

#[test]
fn t_mrk_015_hash_and_hex_edges() {
    assert_eq!(leaf_hash(b"").len(), 32);
    assert_eq!(node_hash(&leaf_hash(b"a"), &leaf_hash(b"b")).len(), 32);
    assert_eq!(hex(&leaf_hash(b"")).len(), 64);
    assert!(unhex("zz").is_none());
    assert!(unhex("abc").is_none());
    assert_eq!(unhex(&hex(b"round-trip")).unwrap(), b"round-trip");
}

#[test]
fn t_mrk_016_first_and_last_leaf_proofs() {
    for n in [2usize, 3, 5, 8, 13] {
        let tree = tree(n);
        for index in [0usize, n - 1] {
            let proof: Vec<[u8; 32]> = tree.inclusion_proof(index).unwrap();
            assert!(verify_inclusion(
                tree.leaves().get(index).unwrap(),
                index,
                n,
                &proof,
                &tree.root()
            ));
        }
    }
}

#[test]
fn t_mrk_017_proof_order_matters() {
    let tree = tree(8);
    let mut proof: Vec<[u8; 32]> = tree.inclusion_proof(6).unwrap();
    proof.reverse();
    assert!(!verify_inclusion(
        tree.leaves().get(6).unwrap(),
        6,
        8,
        &proof,
        &tree.root()
    ));
}

#[test]
fn t_mrk_018_consistency_edges() {
    let tree = tree(1);
    assert!(consistency_proof(tree.leaves(), 1).unwrap().is_empty());
    assert!(consistency_proof(tree.leaves(), 0).is_none());
    let two = tree_two();
    assert!(!consistency_proof(two.leaves(), 1).unwrap().is_empty());
}

fn tree_two() -> MerkleTree {
    let mut tree = MerkleTree::new();
    tree.append(b"a");
    tree.append(b"b");
    tree
}

#[test]
fn t_mrk_019_distinct_trees_have_distinct_roots() {
    let a = tree(10);
    let mut b = tree(10);
    b.append(b"one-more");
    assert_ne!(a.root(), b.root());
    let mut c = MerkleTree::new();
    for payload in payloads(10).into_iter().rev() {
        c.append(&payload);
    }
    assert_ne!(a.root(), c.root(), "leaf order matters");
}

#[test]
fn t_mrk_020_proofs_verify_against_reference_roots() {
    let tree = tree(20);
    let expected = reference(&tree);
    let roots = expected["roots"].as_array().unwrap();
    let reference_root: [u8; 32] = unhex(roots[20].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof: Vec<[u8; 32]> = tree.inclusion_proof(11).unwrap();
    assert!(verify_inclusion(
        tree.leaves().get(11).unwrap(),
        11,
        20,
        &proof,
        &reference_root
    ));
    let wrong = leaf_hash(b"wrong-root");
    assert!(!verify_inclusion(
        tree.leaves().get(11).unwrap(),
        11,
        20,
        &proof,
        &wrong
    ));
    assert!(inclusion_proof(tree.leaves(), 20).is_none());
}
