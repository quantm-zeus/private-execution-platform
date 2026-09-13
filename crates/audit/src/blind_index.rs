//! Keyed blind indexes: equality lookup tokens with no embedded semantics.
//!
//! Every index is `HMAC-SHA256(blind_index_key, domain || ...)` and is exactly
//! 32 bytes. Domains are distinct per lookup class so a token from one class can
//! never collide with another class by construction. Only identifiers that the
//! operator already treats as opaque are indexed: never token symbols, wallets,
//! amounts, sides, venues, outcomes, or any other trading semantics.

use chain_types::ChainId;
use domain::{ExecutionId, IdempotencyKey, IntentId, UserId};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::key::BlindIndexKey;

type HmacSha256 = Hmac<Sha256>;

/// Domain label for the primary per-intent stream index.
pub const STREAM_DOMAIN: &[u8] = b"audit.stream.v1";
/// Domain label for the optional owner index.
pub const OWNER_DOMAIN: &[u8] = b"audit.owner.v1";
/// Domain label for the optional idempotency index.
pub const IDEMPOTENCY_DOMAIN: &[u8] = b"audit.idempotency.v1";
/// Domain label for the optional execution index.
pub const EXECUTION_DOMAIN: &[u8] = b"audit.execution.v1";

const CHAIN_TAG_DOMAIN: &[u8] = b"audit.chain_tag.v1";

/// Fixed-width canonical chain tag.
///
/// Hashing the chain identity to a fixed 32 bytes keeps `chain_tag || intent_id`
/// unambiguous across the variable-length boundary and gives operator-defined
/// `Other` chains a stable, non-leaking tag. The outer HMAC still keys the
/// result, so the tag alone reveals nothing.
fn chain_tag(chain: &ChainId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_TAG_DOMAIN);
    match chain {
        ChainId::Solana => hasher.update(b"solana"),
        ChainId::Base => hasher.update(b"base"),
        ChainId::BnbChain => hasher.update(b"bnb_chain"),
        ChainId::Ethereum => hasher.update(b"ethereum"),
        ChainId::RobinhoodAssociated => hasher.update(b"robinhood_associated"),
        ChainId::Other(id) => {
            hasher.update(b"other");
            hasher.update(id.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Keyed HMAC over `domain` followed by each `part`.
fn derive(key: &BlindIndexKey, domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], AuditError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| AuditError::EventValidationFailed("blind index key length"))?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// `HMAC(key, "audit.stream.v1" || chain_tag || intent_id)`.
pub fn stream_blind_index(
    key: &BlindIndexKey,
    chain: &ChainId,
    intent_id: &IntentId,
) -> Result<[u8; 32], AuditError> {
    let tag = chain_tag(chain);
    derive(key, STREAM_DOMAIN, &[&tag, intent_id.as_str().as_bytes()])
}

/// `HMAC(key, "audit.owner.v1" || user_id)`; optional owner lookup token.
pub fn owner_blind_index(key: &BlindIndexKey, user_id: &UserId) -> Result<[u8; 32], AuditError> {
    derive(key, OWNER_DOMAIN, &[user_id.as_str().as_bytes()])
}

/// `HMAC(key, "audit.idempotency.v1" || idempotency_key)`.
pub fn idempotency_blind_index(
    key: &BlindIndexKey,
    idempotency_key: &IdempotencyKey,
) -> Result<[u8; 32], AuditError> {
    derive(
        key,
        IDEMPOTENCY_DOMAIN,
        &[idempotency_key.as_str().as_bytes()],
    )
}

/// `HMAC(key, "audit.execution.v1" || execution_id)`.
pub fn execution_blind_index(
    key: &BlindIndexKey,
    execution_id: &ExecutionId,
) -> Result<[u8; 32], AuditError> {
    derive(key, EXECUTION_DOMAIN, &[execution_id.as_str().as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{IdempotencyKey, IntentId};
    use std::collections::HashSet;

    fn key(fill: u8) -> BlindIndexKey {
        BlindIndexKey::from_bytes([fill; 32])
    }

    fn intent(value: &str) -> IntentId {
        IntentId::new(value).expect("intent")
    }

    #[test]
    fn stream_index_is_deterministic_and_full_width() {
        let k = key(7);
        let a = stream_blind_index(&k, &ChainId::Base, &intent("intent-alpha")).expect("a");
        let b = stream_blind_index(&k, &ChainId::Base, &intent("intent-alpha")).expect("b");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn distinct_intents_and_chains_differ() {
        let k = key(7);
        let a = stream_blind_index(&k, &ChainId::Base, &intent("intent-alpha")).expect("a");
        let b = stream_blind_index(&k, &ChainId::Base, &intent("intent-beta")).expect("b");
        let c = stream_blind_index(&k, &ChainId::Solana, &intent("intent-alpha")).expect("c");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn domains_are_separated() {
        let k = key(7);
        let intent_id = intent("intent-alpha");
        let stream = stream_blind_index(&k, &ChainId::Base, &intent_id).expect("stream");
        let owner =
            owner_blind_index(&k, &UserId::new("user-alpha").expect("user")).expect("owner");
        let idem = idempotency_blind_index(&k, &IdempotencyKey::new("idem-alpha").expect("idem"))
            .expect("idem");
        let exec = execution_blind_index(&k, &ExecutionId::new("exec-alpha").expect("exec"))
            .expect("exec");

        let mut tokens = HashSet::new();
        assert!(tokens.insert(stream));
        assert!(tokens.insert(owner));
        assert!(tokens.insert(idem));
        assert!(tokens.insert(exec));
        assert_eq!(tokens.len(), 4);
    }

    #[test]
    fn changing_key_changes_token() {
        let a = stream_blind_index(&key(1), &ChainId::Base, &intent("intent-alpha")).expect("a");
        let b = stream_blind_index(&key(2), &ChainId::Base, &intent("intent-alpha")).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn token_contains_no_identifier_substring() {
        let index =
            stream_blind_index(&key(7), &ChainId::Base, &intent("intent-alpha")).expect("index");
        let haystack = format!("{index:?}");
        assert!(!haystack.contains("intent-alpha"));
        assert!(!haystack.contains("user"));
        assert!(!haystack.contains("wallet"));
        assert!(!format!("{index:?}").contains("intent"));
    }
}
