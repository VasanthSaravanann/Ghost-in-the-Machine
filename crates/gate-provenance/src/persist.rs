//! redb-backed persistence for provenance (plan.md M2-T05, T-PER-001..016).
//!
//! `redb` is copy-on-write and ACID: there is no separate WAL — durability comes
//! from the commit path, and an uncommitted transaction (crash, `kill -9`) is
//! simply absent from the reopened database. The in-memory [`crate::ProvenanceStore`]
//! remains the fast path; every mutation is written through in one committed
//! transaction, and a failed write rolls the in-memory state back to the last
//! committed state (the database is the source of truth on failure).

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
use std::path::Path;

use gate_core::{Label, SegmentId};
use redb::{Database, ReadableTable, TableDefinition};

use crate::{ProvenanceStore, Segment, SegmentSpec};

const SEGMENTS: TableDefinition<&str, &str> = TableDefinition::new("segments");
const ENDORSED: TableDefinition<&str, &str> = TableDefinition::new("endorsed");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistError {
    Store(String),
    Txn(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(detail) => write!(f, "provenance store error: {detail}"),
            Self::Txn(detail) => write!(f, "transaction error: {detail}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl From<crate::ProvenanceError> for PersistError {
    fn from(e: crate::ProvenanceError) -> Self {
        Self::Store(e.to_string())
    }
}

/// A segment plus the provenance facts needed to survive a session restart:
/// label and full ancestry (the plan's "memory-record API").
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryRecord {
    pub segment: Segment,
    /// Meet of every label in the recorded ancestry.
    pub label: Label,
    pub ancestry: Vec<String>,
}

/// redb-backed provenance store with write-through semantics.
pub struct PersistentStore {
    path: std::path::PathBuf,
    inner: ProvenanceStore,
    db: redb::Database,
}

impl std::fmt::Debug for PersistentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentStore")
            .field("path", &self.path)
            .field("segments", &self.inner.len())
            .finish()
    }
}

impl PersistentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        let path = path.as_ref().to_path_buf();
        // Pre-flight corruption guard: redb asserts (panics) on a truncated or
        // garbled file. A torn file must surface as an error so the gate can fail
        // closed instead of panicking in the authorisation path.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() < 4096 {
                return Err(PersistError::Store(format!(
                    "{} is too small to be a redb database ({} bytes)",
                    path.display(),
                    meta.len()
                )));
            }
        }
        let db = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Database::create(&path)))
            .map_err(|_| {
                PersistError::Store(format!("{} is not a valid database", path.display()))
            })?
            .map_err(|e| PersistError::Store(format!("create {}: {e}", path.display())))?;
        // Ensure both tables exist before the first read (redb creates tables in
        // write transactions; a fresh database has none).
        {
            let write = db
                .begin_write()
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .open_table(SEGMENTS)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .open_table(ENDORSED)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            write
                .commit()
                .map_err(|e| PersistError::Txn(e.to_string()))?;
        }
        let inner = Self::load(&db)?;
        Ok(Self { path, inner, db })
    }

    fn load(db: &redb::Database) -> Result<ProvenanceStore, PersistError> {
        let read = db
            .begin_read()
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        let table = read
            .open_table(SEGMENTS)
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        let mut segments: Vec<Segment> = Vec::new();
        for entry in table.iter().map_err(|e| PersistError::Txn(e.to_string()))? {
            let (key, value) = entry.map_err(|e| PersistError::Txn(e.to_string()))?;
            let segment: Segment = serde_json::from_str(value.value()).map_err(|e| {
                PersistError::Store(format!("corrupt segment {}: {e}", key.value()))
            })?;
            segments.push(segment);
        }

        let endorsed_table = read
            .open_table(ENDORSED)
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        let mut endorsed: BTreeMap<String, String> = BTreeMap::new();
        for entry in endorsed_table
            .iter()
            .map_err(|e| PersistError::Txn(e.to_string()))?
        {
            let (source, digest) = entry.map_err(|e| PersistError::Txn(e.to_string()))?;
            endorsed.insert(source.value().to_owned(), digest.value().to_owned());
        }

        let mut inner = ProvenanceStore::new();
        for (source, digest) in &endorsed {
            inner.register_endorsed_source(source, digest);
        }
        // Insert in dependency order: a segment whose parents are not yet
        // present is deferred (a consistent store always resolves).
        let mut pending: Vec<Segment> = segments;
        let mut progress = true;
        while progress && !pending.is_empty() {
            progress = false;
            let mut next = Vec::new();
            for segment in pending {
                if segment.parents.iter().all(|p| inner.segment(p).is_some()) {
                    let inserted = inner.insert(SegmentSpec::from_segment(&segment))?;
                    debug_assert_eq!(inserted.id, segment.id);
                    progress = true;
                } else {
                    next.push(segment);
                }
            }
            pending = next;
        }
        if !pending.is_empty() {
            return Err(PersistError::Store(
                "persisted segments contain missing parents".into(),
            ));
        }
        Ok(inner)
    }

    /// Write the whole in-memory state in one committed transaction.
    fn persist_all(&mut self) -> Result<(), PersistError> {
        let write = self
            .db
            .begin_write()
            .map_err(|e| PersistError::Txn(e.to_string()))?;
        {
            let mut segments = write
                .open_table(SEGMENTS)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            segments
                .retain(|_key, _value| false)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            for id in self.inner.ids() {
                let segment = self
                    .inner
                    .segment(&id)
                    .ok_or_else(|| PersistError::Store("missing segment".into()))?;
                let value = serde_json::to_string(segment)
                    .map_err(|e| PersistError::Store(e.to_string()))?;
                segments
                    .insert(id.as_str(), value.as_str())
                    .map_err(|e| PersistError::Txn(e.to_string()))?;
            }
            let mut endorsed = write
                .open_table(ENDORSED)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            endorsed
                .retain(|_key, _value| false)
                .map_err(|e| PersistError::Txn(e.to_string()))?;
            for (source, digest) in self.inner.endorsed_entries() {
                endorsed
                    .insert(source.as_str(), digest.as_str())
                    .map_err(|e| PersistError::Txn(e.to_string()))?;
            }
        }
        write.commit().map_err(|e| PersistError::Txn(e.to_string()))
    }

    /// Write through: mutate the in-memory store first, then commit everything.
    /// On any failure the in-memory state is rolled back to the committed
    /// database, so a read after a failure never sees a torn session.
    pub fn insert(&mut self, spec: SegmentSpec) -> Result<Segment, PersistError> {
        let inserted = self.inner.insert(spec)?;
        if self.persist_all().is_err() {
            self.inner = Self::load(&self.db)?;
            return Err(PersistError::Txn(
                "write failed; state restored from committed database".into(),
            ));
        }
        Ok(inserted)
    }

    pub fn register_endorsed(
        &mut self,
        source: impl Into<String>,
        content_digest: &str,
    ) -> Result<(), PersistError> {
        self.inner.register_endorsed_source(source, content_digest);
        self.persist_all()
    }

    #[must_use]
    pub fn segment(&self, id: &SegmentId) -> Option<&Segment> {
        self.inner.segment(id)
    }

    #[must_use]
    pub fn ids(&self) -> Vec<SegmentId> {
        self.inner.ids()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub fn ancestry(&self, id: &SegmentId) -> std::collections::BTreeSet<SegmentId> {
        self.inner.ancestry(id)
    }

    /// Memory record for one segment, including its full ancestry.
    #[must_use]
    pub fn memory_record(&self, id: &SegmentId) -> Option<MemoryRecord> {
        let segment = self.inner.segment(id)?.clone();
        let ancestry: Vec<String> = self
            .inner
            .ancestry(id)
            .into_iter()
            .map(|a| a.to_string())
            .collect();
        let labels: Vec<Label> = ancestry
            .iter()
            .filter_map(|a| self.inner.label_of(&SegmentId::from(a.as_str())))
            .collect();
        let label = Label::derive(labels.iter());
        Some(MemoryRecord {
            segment,
            label,
            ancestry,
        })
    }

    /// Recover a memory record in a *new* session. The recovered label is the
    /// meet of the stored label and every known ancestor label, so a restart can
    /// never make anything more trusted (T-PER-001).
    #[must_use]
    pub fn recover_label(&self, record: &MemoryRecord) -> Label {
        let mut labels = vec![record.label];
        for ancestor in &record.ancestry {
            if let Some(label) = self.inner.label_of(&SegmentId::from(ancestor.as_str())) {
                labels.push(label);
            }
        }
        Label::derive(labels.iter())
    }
}

/// Summarisation = derivation: the summary of mixed-label content takes the
/// meet (T-PER-004) and can only be written under a parent set it derives from.
#[must_use]
pub fn summarise(store: &ProvenanceStore, ids: &[SegmentId]) -> Option<SegmentSpec> {
    summarise_provenance(|id| store.label_of(id), ids)
}

/// Store-shape-agnostic helper used by the tests to build a summary spec from
/// the persistent store.
#[must_use]
pub fn summarise_provenance(
    labels: impl Fn(&SegmentId) -> Option<Label>,
    ids: &[SegmentId],
) -> Option<SegmentSpec> {
    let found: Vec<Label> = ids.iter().filter_map(labels).collect();
    if found.is_empty() {
        return None;
    }
    let label = Label::derive(found.iter());
    let mut content = String::from("summary[");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            content.push(',');
        }
        content.push_str(id.as_str());
    }
    content.push(']');
    Some(SegmentSpec::new(
        label,
        crate::SourceRef::new("memory:summary"),
        content,
        ids.to_vec(),
        u64::MAX,
    ))
}

// ---------------------------------------------------------- vector adapter

/// Round-trip adapter: embeddings never carry a label — the label travels next
/// to them in the store and is restored on retrieval (T-PER-003).
pub trait VectorStore: Send + Sync {
    fn put(&mut self, id: &str, embedding: &[f32], label: Label, payload_digest: &str);
    fn get(&self, id: &str) -> Option<(Vec<f32>, Label, String)>;
}

#[derive(Debug, Default)]
pub struct InMemoryVectorStore {
    entries: Vec<(String, Vec<f32>, Label, String)>,
}

impl InMemoryVectorStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl VectorStore for InMemoryVectorStore {
    fn put(&mut self, id: &str, embedding: &[f32], label: Label, payload_digest: &str) {
        self.entries.push((
            id.to_owned(),
            embedding.to_vec(),
            label,
            payload_digest.to_owned(),
        ));
    }

    fn get(&self, id: &str) -> Option<(Vec<f32>, Label, String)> {
        self.entries
            .iter()
            .rev()
            .find(|(stored, _, _, _)| stored == id)
            .map(|(_, e, l, p)| (e.clone(), *l, p.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_adapter_preserves_label() {
        let mut store = InMemoryVectorStore::new();
        store.put("v1", &[0.1, 0.2], Label::ExternalUntrustedData, "sha256:ab");
        let (_, label, digest) = store.get("v1").unwrap();
        assert_eq!(label, Label::ExternalUntrustedData);
        assert_eq!(digest, "sha256:ab");
        assert!(store.get("missing").is_none());
    }
}
