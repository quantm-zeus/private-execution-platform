//! Blind indexes are deterministic, domain-separated, keyed tokens.

mod support;

use std::collections::HashSet;

use audit::{
    execution_blind_index, idempotency_blind_index, owner_blind_index, stream_blind_index,
    BlindIndexKey,
};
use support::{base, execution_id, idempotency_key, intent_id, user_id, BLIND_A, BLIND_B, INTENT};

fn key(fill: [u8; 32]) -> BlindIndexKey {
    BlindIndexKey::from_bytes(fill)
}

#[test]
fn stream_index_is_deterministic_for_the_same_intent() {
    let first = stream_blind_index(&key(BLIND_A), &base(), &intent_id(INTENT)).expect("first");
    let second = stream_blind_index(&key(BLIND_A), &base(), &intent_id(INTENT)).expect("second");
    assert_eq!(first, second);
    assert_eq!(first.len(), 32);
}

#[test]
fn different_intents_and_chains_differ() {
    let a = stream_blind_index(&key(BLIND_A), &base(), &intent_id(INTENT)).expect("a");
    let b = stream_blind_index(&key(BLIND_A), &base(), &intent_id("intent-beta")).expect("b");
    assert_ne!(a, b);
    let other_chain = stream_blind_index(
        &key(BLIND_A),
        &chain_types::ChainId::Solana,
        &intent_id(INTENT),
    )
    .expect("other chain");
    assert_ne!(a, other_chain);
}

#[test]
fn domain_labels_separate_index_classes() {
    let k = key(BLIND_A);
    let stream = stream_blind_index(&k, &base(), &intent_id(INTENT)).expect("stream");
    let owner = owner_blind_index(&k, &user_id(INTENT)).expect("owner");
    let idempotency = idempotency_blind_index(&k, &idempotency_key(INTENT)).expect("idempotency");
    let execution = execution_blind_index(&k, &execution_id(INTENT)).expect("execution");

    let mut tokens = HashSet::new();
    assert!(tokens.insert(stream));
    assert!(tokens.insert(owner));
    assert!(tokens.insert(idempotency));
    assert!(tokens.insert(execution));
    assert_eq!(tokens.len(), 4, "each domain must yield a distinct token");
}

#[test]
fn changing_blind_index_key_changes_the_token() {
    let a = stream_blind_index(&key(BLIND_A), &base(), &intent_id(INTENT)).expect("a");
    let b = stream_blind_index(&key(BLIND_B), &base(), &intent_id(INTENT)).expect("b");
    assert_ne!(a, b);
}

#[test]
fn token_reveals_no_identifier_substring() {
    let token = stream_blind_index(&key(BLIND_A), &base(), &intent_id(INTENT)).expect("token");
    let rendered = format!("{token:?}");
    assert!(!rendered.contains(INTENT));
    assert!(!rendered.contains("intent"));
    assert!(!rendered.contains("wallet"));
    assert!(!rendered.contains("user"));
}
