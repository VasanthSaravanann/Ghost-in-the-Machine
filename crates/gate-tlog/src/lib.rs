//! gate-tlog — RFC 9162 Merkle tree, inclusion and consistency proofs
//! (plan.md M4-T01, P4-R1/R4, INV-9 inputs).
//!
//! Domain separation is mandatory: leaves are `SHA256(0x00 ‖ data)` and nodes
//! are `SHA256(0x01 ‖ left ‖ right)` (T-MRK-006), so a leaf can never be
//! reinterpreted as an interior node. Proofs are cross-checked against the
//! independent implementation in `ref/merkle_ref.py` (T-MRK-001/002/004).

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

use std::path::{Path, PathBuf};

use gate_crypto::sha256;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

const LEAVES: TableDefinition<u64, &[u8]> = TableDefinition::new("leaves");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const TREE_HEAD: &str = "tree_head";

#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256(&buf)
}

#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256(&buf)
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << ((n - 1).ilog2())
}

/// MTH over leaf hashes: `MTH({}) = SHA256("")`, `MTH({h}) = h`.
#[must_use]
pub fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(b""),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            let (left, right) = leaves.split_at(k);
            node_hash(&mth(left), &mth(right))
        }
    }
}

/// RFC 9162 §2.1.3.2 `PATH(m, D[n])`, ordered leaf → root.
#[must_use]
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    Some(path(leaves, index))
}

fn path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    let (left, right) = leaves.split_at(k);
    if index < k {
        let mut proof = path(left, index);
        proof.push(mth(right));
        proof
    } else {
        let mut proof = path(right, index - k);
        proof.push(mth(left));
        proof
    }
}

/// RFC 9162 §2.1.4.2 `SUBPROOF(m, D[n], b)`; `PROOF(m, D[n]) = SUBPROOF(m, D[n], true)`.
#[must_use]
pub fn consistency_proof(leaves: &[Hash], first: usize) -> Option<Vec<Hash>> {
    if first == 0 || first > leaves.len() {
        return None;
    }
    Some(subproof(leaves, first, true))
}

fn subproof(leaves: &[Hash], m: usize, complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete {
            Vec::new()
        } else {
            vec![mth(leaves)]
        };
    }
    let k = split_point(n);
    let (left, right) = leaves.split_at(k);
    if m <= k {
        let mut proof = subproof(left, m, complete);
        proof.push(mth(right));
        proof
    } else {
        let mut proof = subproof(right, m - k, false);
        proof.push(mth(left));
        proof
    }
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2).
#[must_use]
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut function_index = index;
    let mut tree_index = tree_size - 1;
    let mut running = *leaf;
    for sibling in proof {
        if tree_index == 0 {
            return false;
        }
        if function_index & 1 == 1 || function_index == tree_index {
            running = node_hash(sibling, &running);
            while function_index & 1 == 0 && function_index != 0 {
                function_index >>= 1;
                tree_index >>= 1;
            }
        } else {
            running = node_hash(&running, sibling);
        }
        function_index >>= 1;
        tree_index >>= 1;
    }
    tree_index == 0 && running == *root
}

/// One inclusion-proof bundle, ready for `mcp-audit verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionBundle {
    pub index: usize,
    pub tree_size: usize,
    pub leaf: String,
    pub root: String,
    pub proof: Vec<String>,
}

impl InclusionBundle {
    #[must_use]
    pub fn new(tree: &MerkleTree, index: usize) -> Option<Self> {
        let leaf = *tree.leaf(index)?;
        let proof = inclusion_proof(tree.leaves(), index)?;
        Some(Self {
            index,
            tree_size: tree.len(),
            leaf: hex(&leaf),
            root: hex(&tree.root()),
            proof: proof.iter().map(|h| hex(h)).collect(),
        })
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let (Some(leaf), Some(root)) = (unhex(&self.leaf), unhex(&self.root)) else {
            return false;
        };
        let (Ok(leaf), Ok(root)) = (hashed(&leaf), hashed(&root)) else {
            return false;
        };
        let Some(proof) = self
            .proof
            .iter()
            .map(|p| unhex(p).and_then(|b| hashed(&b).ok()))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        verify_inclusion(&leaf, self.index, self.tree_size, &proof, &root)
    }
}

fn hashed(bytes: &[u8]) -> Result<Hash, ()> {
    let arr: Hash = bytes.try_into().map_err(|_| ())?;
    Ok(arr)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// In-memory tree plus optional redb persistence (storage on redb, §2.4).
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
}

impl MerkleTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_leaf_hashes(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    #[must_use]
    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    #[must_use]
    pub fn leaf(&self, index: usize) -> Option<&Hash> {
        self.leaves.get(index)
    }

    /// Append a payload; returns its leaf hash.
    pub fn append(&mut self, data: &[u8]) -> Hash {
        let hash = leaf_hash(data);
        self.leaves.push(hash);
        hash
    }

    #[must_use]
    pub fn root(&self) -> Hash {
        mth(&self.leaves)
    }

    #[must_use]
    pub fn root_at(&self, size: usize) -> Option<Hash> {
        if size > self.leaves.len() {
            return None;
        }
        Some(mth(self.leaves.get(..size).unwrap_or_default()))
    }

    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<Hash>> {
        inclusion_proof(&self.leaves, index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistError {
    Store(String),
    Txn(String),
    Corrupt(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(d) => write!(f, "tlog store error: {d}"),
            Self::Txn(d) => write!(f, "tlog transaction error: {d}"),
            Self::Corrupt(d) => write!(f, "tlog corruption: {d}"),
        }
    }
}

impl std::error::Error for PersistError {}

/// redb-backed append-only leaf log; reopening restores the tree (T-MRK-007).
pub struct TreeStore {
    path: PathBuf,
    db: Database,
    tree: MerkleTree,
}

impl std::fmt::Debug for TreeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeStore")
            .field("path", &self.path)
            .field("leaves", &self.tree.len())
            .finish()
    }
}

impl TreeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        let path = path.as_ref().to_path_buf();
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() < 4096 {
                return Err(PersistError::Corrupt(format!(
                    "{} is too small",
                    path.display()
                )));
            }
        }
        let db = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Database::create(&path)))
            .map_err(|_| PersistError::Corrupt(format!("{} is not a database", path.display())))?
            .map_err(|e| PersistError::Store(format!("create {}: {e}", path.display())))?;
        {
            let write = db
                .begin_write()
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .open_table(LEAVES)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .open_table(META)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .commit()
                .map_err(|e| PersistError::Txn(e.to_string()))?;
        }
        let mut tree = MerkleTree::new();
        {
            let read = db
                .begin_read()
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            let table = read
                .open_table(LEAVES)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            for entry in table.iter().map_err(|e| PersistError::Txn(e.to_string()))? {
                let (_, value) = entry.map_err(|e| PersistError::Txn(e.to_string()))?;
                let bytes = value.value();
                if bytes.len() != 32 {
                    return Err(PersistError::Corrupt("leaf is not 32 bytes".into()));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                tree.leaves.push(hash);
            }
        }
        Ok(Self { path, db, tree })
    }

    pub fn append(&mut self, data: &[u8]) -> Result<Hash, PersistError> {
        let index = self.tree.len() as u64;
        let hash = self.tree.append(data);
        let write = self
            .db
            .begin_write()
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        {
            let mut leaves = write
                .open_table(LEAVES)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            leaves
                .insert(index, hash.as_slice())
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            let mut meta = write
                .open_table(META)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            meta.insert(TREE_HEAD, self.tree.root().as_slice())
                .map_err(|e| PersistError::Txn(e.to_string()))?;
        }
        write
            .commit()
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        Ok(hash)
    }

    #[must_use]
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}
