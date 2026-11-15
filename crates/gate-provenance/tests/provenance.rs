//! T-PRV-001..015 (plan.md §5.7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::{Label, SegmentId};
use gate_provenance::{ProvenanceError, ProvenanceStore, SegmentSpec, SourceRef};
use proptest::prelude::*;

fn seg(label: Label, source: &str, content: &str, parents: &[SegmentId], turn: u64) -> SegmentSpec {
    SegmentSpec::new(
        label,
        SourceRef::new(source),
        content,
        parents.to_vec(),
        turn,
    )
}

fn label_strategy() -> impl Strategy<Value = Label> {
    prop_oneof![
        Just(Label::ExternalUntrustedData),
        Just(Label::EndorsedCorpus),
        Just(Label::PrincipalDirect),
    ]
}

#[test]
fn t_prv_001_one_label_per_segment() {
    let mut store = ProvenanceStore::new();
    let s = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "tool:notes",
            "hello",
            &[],
            0,
        ))
        .unwrap();
    assert_eq!(s.label, Label::ExternalUntrustedData);
    assert_eq!(store.segment(&s.id).unwrap().label, s.label);
    assert_eq!(store.len(), 1);
}

#[test]
fn t_prv_002_derive_is_meet() {
    assert_eq!(
        Label::derive([Label::PrincipalDirect, Label::ExternalUntrustedData].iter()),
        Label::ExternalUntrustedData
    );
    assert_eq!(
        Label::derive([Label::PrincipalDirect, Label::EndorsedCorpus].iter()),
        Label::EndorsedCorpus
    );
}

#[test]
fn t_prv_003_deep_chain_never_rises() {
    let mut store = ProvenanceStore::new();
    let mut parent = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "tool:ticket",
            "ticket #8841",
            &[],
            0,
        ))
        .unwrap();
    for depth in 1..=1_000 {
        let child = store
            .insert(seg(
                Label::ExternalUntrustedData,
                &format!("agent:derive-{depth}"),
                &format!("derived {depth} of {}", parent.content_digest),
                &[parent.id.clone()],
                depth,
            ))
            .unwrap();
        assert!(child.label <= parent.label, "label rose at depth {depth}");
        assert_eq!(child.label, Label::ExternalUntrustedData);
        parent = child;
    }
    assert_eq!(store.len(), 1_001);
}

#[test]
fn t_prv_004_ancestry_dag() {
    let mut store = ProvenanceStore::new();
    let root = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "a", &[], 0))
        .unwrap();
    let mid = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "tool:b",
            "b",
            &[root.id.clone()],
            1,
        ))
        .unwrap();
    let leaf = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "principal",
            "c",
            &[mid.id.clone()],
            2,
        ))
        .unwrap();
    let ancestry = store.ancestry(&leaf.id);
    assert!(ancestry.contains(&leaf.id));
    assert!(ancestry.contains(&mid.id));
    assert!(ancestry.contains(&root.id));
    let missing = SegmentId::from("seg_does_not_exist");
    assert_eq!(
        store.insert(seg(Label::PrincipalDirect, "x", "x", &[missing.clone()], 3)),
        Err(ProvenanceError::UnknownParent(missing))
    );
}

#[test]
fn t_prv_005_endorsed_source() {
    let mut store = ProvenanceStore::new();
    let digest = gate_crypto::sha256_hex(b"Q3 report, approved");
    store.register_endorsed_source("corpus:q3", &digest);
    let s = store
        .insert(seg(
            Label::PrincipalDirect,
            "corpus:q3",
            "Q3 report, approved",
            &[],
            0,
        ))
        .unwrap();
    assert_eq!(s.label, Label::EndorsedCorpus);
}

#[test]
fn t_prv_006_tampered_endorsed_demoted() {
    let mut store = ProvenanceStore::new();
    let digest = gate_crypto::sha256_hex(b"Q3 report, approved");
    store.register_endorsed_source("corpus:q3", &digest);
    let s = store
        .insert(seg(
            Label::PrincipalDirect,
            "corpus:q3",
            "Q3 report, approved + exfil",
            &[],
            0,
        ))
        .unwrap();
    assert_eq!(s.label, Label::ExternalUntrustedData);
}

#[test]
fn t_prv_007_endorsed_derivation() {
    let mut store = ProvenanceStore::new();
    let digest = gate_crypto::sha256_hex(b"approved text");
    store.register_endorsed_source("corpus:x", &digest);
    let endorsed = store
        .insert(seg(
            Label::PrincipalDirect,
            "corpus:x",
            "approved text",
            &[],
            0,
        ))
        .unwrap();
    let tool = store
        .insert(seg(Label::ExternalUntrustedData, "tool:web", "web", &[], 0))
        .unwrap();
    let derived = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "agent:mix",
            "mix",
            &[endorsed.id, tool.id],
            1,
        ))
        .unwrap();
    assert_eq!(derived.label, Label::ExternalUntrustedData);
}

#[test]
fn t_prv_008_idempotent_insert() {
    let mut store = ProvenanceStore::new();
    let a = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "same", &[], 0))
        .unwrap();
    let b = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "same", &[], 0))
        .unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(store.len(), 1);
}

#[test]
fn t_prv_009_content_addressed_ids() {
    let mut store = ProvenanceStore::new();
    let p1 = store
        .insert(seg(Label::ExternalUntrustedData, "t1", "one", &[], 0))
        .unwrap();
    let p2 = store
        .insert(seg(Label::ExternalUntrustedData, "t2", "two", &[], 0))
        .unwrap();
    let a = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "agent",
            "out",
            &[p1.id.clone(), p2.id.clone()],
            1,
        ))
        .unwrap();
    let b = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "agent",
            "out",
            &[p2.id.clone(), p1.id.clone()],
            1,
        ))
        .unwrap();
    assert_eq!(a.id, b.id);
    let different = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "agent",
            "out!",
            &[p1.id, p2.id],
            1,
        ))
        .unwrap();
    assert_ne!(a.id, different.id);
}

#[test]
fn t_prv_010_taint_cannot_be_raised() {
    let mut store = ProvenanceStore::new();
    let tainted = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "evil", &[], 0))
        .unwrap();
    let err = store
        .insert(seg(
            Label::PrincipalDirect,
            "agent:clean",
            "clean",
            &[tainted.id.clone()],
            1,
        ))
        .unwrap_err();
    assert!(matches!(err, ProvenanceError::TaintRaised { .. }));
    let ok = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "agent:clean",
            "clean",
            &[tainted.id],
            1,
        ))
        .unwrap();
    assert_eq!(ok.label, Label::ExternalUntrustedData);
}

#[test]
fn t_prv_011_ancestry_deterministic() {
    let mut store = ProvenanceStore::new();
    let root = store
        .insert(seg(Label::ExternalUntrustedData, "t", "r", &[], 0))
        .unwrap();
    let mut parents = vec![root.id];
    for i in 0..20 {
        let s = store
            .insert(seg(
                Label::ExternalUntrustedData,
                &format!("t{i}"),
                &format!("v{i}"),
                &parents.clone(),
                1,
            ))
            .unwrap();
        parents.push(s.id);
    }
    let leaf = parents.last().cloned().unwrap();
    let a = store.ancestry(&leaf);
    let b = store.ancestry(&leaf);
    assert_eq!(a, b);
    let ordered: Vec<_> = a.iter().cloned().collect();
    let mut sorted = ordered.clone();
    sorted.sort();
    assert_eq!(ordered, sorted);
}

#[test]
fn t_prv_012_multiple_parents_meet() {
    let mut store = ProvenanceStore::new();
    let a = store
        .insert(seg(Label::PrincipalDirect, "p", "a", &[], 0))
        .unwrap();
    let b = store
        .insert(seg(Label::EndorsedCorpus, "c", "b", &[], 0))
        .unwrap();
    let c = store
        .insert(seg(Label::ExternalUntrustedData, "u", "c", &[], 0))
        .unwrap();
    let d = store
        .insert(seg(
            Label::ExternalUntrustedData,
            "x",
            "d",
            &[a.id, b.id, c.id],
            1,
        ))
        .unwrap();
    assert_eq!(d.label, Label::ExternalUntrustedData);
    assert_eq!(d.parent_label, Some(Label::ExternalUntrustedData));
}

#[test]
fn t_prv_013_turn_windows() {
    let mut store = ProvenanceStore::new();
    let a = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "same", &[], 0))
        .unwrap();
    let b = store
        .insert(seg(Label::ExternalUntrustedData, "tool:b", "other", &[], 1))
        .unwrap();
    let a2 = store
        .insert(seg(Label::ExternalUntrustedData, "tool:a", "same", &[], 2))
        .unwrap();
    assert_eq!(a.id, a2.id);
    assert_eq!(store.turn_window(0), vec![a.id.clone()]);
    assert_eq!(store.turn_window(1), vec![b.id]);
    assert_eq!(store.turn_window(2), vec![a.id]);
    assert!(store.turn_window(99).is_empty());
}

#[test]
fn t_prv_014_empty_derivation() {
    let store = ProvenanceStore::new();
    assert_eq!(store.derived_label(&[]), None);
    assert_eq!(store.label_of(&SegmentId::from("seg_missing")), None);
    assert_eq!(store.ancestry(&SegmentId::from("seg_missing")).len(), 1);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn t_prv_015_derivation_monotone(a in label_strategy(), b in label_strategy(), c in label_strategy()) {
        let mut store = ProvenanceStore::new();
        let p1 = store.insert(SegmentSpec::new(a, SourceRef::new("p1"), "1", vec![], 0)).unwrap();
        let p2 = store.insert(SegmentSpec::new(b, SourceRef::new("p2"), "2", vec![], 0)).unwrap();
        let p3 = store.insert(SegmentSpec::new(c, SourceRef::new("p3"), "3", vec![], 0)).unwrap();
        let child = store.insert(SegmentSpec::new(
            a.min(b).min(c),
            SourceRef::new("child"),
            "out",
            vec![p1.id.clone(), p2.id.clone(), p3.id.clone()],
            1,
        )).unwrap();
        prop_assert!(child.label <= p1.label);
        prop_assert!(child.label <= p2.label);
        prop_assert!(child.label <= p3.label);
    }
}
