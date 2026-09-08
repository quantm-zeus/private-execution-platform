//! Chain-neutral identifiers used by the canonical trading domain.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ChainId {
    Solana,
    Base,
    BnbChain,
    Ethereum,
    RobinhoodAssociated,
    Other(#[serde(deserialize_with = "deserialize_custom_chain")] String),
}

impl ChainId {
    pub fn validate(&self) -> Result<(), ChainTypeError> {
        if let Self::Other(value) = self {
            ensure_custom_chain_id(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId {
    pub chain: ChainId,
    #[serde(deserialize_with = "deserialize_asset_address")]
    pub address: String,
}

impl AssetId {
    pub fn new(chain: ChainId, address: impl Into<String>) -> Result<Self, ChainTypeError> {
        chain.validate()?;
        let address = address.into();
        ensure_asset_address(&address)?;
        Ok(Self { chain, address })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainTypeError {
    #[error("custom chain identifier must not be empty")]
    EmptyChainId,
    #[error("asset address must not be empty")]
    EmptyAssetAddress,
}

fn ensure_custom_chain_id(value: &str) -> Result<(), ChainTypeError> {
    if value.trim().is_empty() {
        return Err(ChainTypeError::EmptyChainId);
    }
    Ok(())
}

fn ensure_asset_address(address: &str) -> Result<(), ChainTypeError> {
    if address.trim().is_empty() {
        return Err(ChainTypeError::EmptyAssetAddress);
    }
    Ok(())
}

fn deserialize_custom_chain<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    ensure_custom_chain_id(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_asset_address<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let address = String::deserialize(deserializer)?;
    ensure_asset_address(&address).map_err(serde::de::Error::custom)?;
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_id_round_trips() {
        let asset = AssetId::new(ChainId::Base, "0xabc").unwrap();
        let encoded = serde_json::to_string(&asset).unwrap();
        let decoded: AssetId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, asset);
    }

    #[test]
    fn empty_asset_is_rejected() {
        assert_eq!(
            AssetId::new(ChainId::Solana, "  "),
            Err(ChainTypeError::EmptyAssetAddress)
        );
    }

    #[test]
    fn empty_custom_chain_is_rejected() {
        assert_eq!(
            ChainId::Other("   ".to_string()).validate(),
            Err(ChainTypeError::EmptyChainId)
        );
        assert_eq!(
            AssetId::new(ChainId::Other("".to_string()), "0xabc"),
            Err(ChainTypeError::EmptyChainId)
        );
    }

    #[test]
    fn deserialization_rejects_blank_custom_chain() {
        assert!(serde_json::from_str::<ChainId>(r#"{"kind":"other","value":"   "}"#).is_err());
        assert!(serde_json::from_str::<AssetId>(
            r#"{"chain":{"kind":"other","value":""},"address":"0xabc"}"#
        )
        .is_err());
    }

    #[test]
    fn deserialization_rejects_blank_asset_address() {
        assert!(
            serde_json::from_str::<AssetId>(r#"{"chain":{"kind":"base"},"address":"  "}"#).is_err()
        );
        assert!(
            serde_json::from_str::<AssetId>(r#"{"chain":{"kind":"solana"},"address":""}"#).is_err()
        );
    }

    #[test]
    fn built_in_chains_round_trip() {
        for chain in [
            ChainId::Solana,
            ChainId::Base,
            ChainId::BnbChain,
            ChainId::Ethereum,
            ChainId::RobinhoodAssociated,
        ] {
            let encoded = serde_json::to_string(&chain).unwrap();
            let decoded: ChainId = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, chain);
        }
        assert_eq!(
            serde_json::to_string(&ChainId::Solana).unwrap(),
            r#"{"kind":"solana"}"#
        );
        assert_eq!(
            serde_json::to_string(&ChainId::BnbChain).unwrap(),
            r#"{"kind":"bnb_chain"}"#
        );
        assert_eq!(
            serde_json::to_string(&ChainId::RobinhoodAssociated).unwrap(),
            r#"{"kind":"robinhood_associated"}"#
        );
    }

    #[test]
    fn custom_chain_round_trips() {
        let chain = ChainId::Other("hypercore".to_string());
        assert_eq!(
            serde_json::to_string(&chain).unwrap(),
            r#"{"kind":"other","value":"hypercore"}"#
        );
        let encoded = serde_json::to_string(&chain).unwrap();
        let decoded: ChainId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, chain);
    }

    #[test]
    fn custom_chain_asset_round_trips() {
        let asset = AssetId::new(ChainId::Other("custom-chain".to_string()), "0xdead").unwrap();
        let encoded = serde_json::to_string(&asset).unwrap();
        assert_eq!(
            encoded,
            r#"{"chain":{"kind":"other","value":"custom-chain"},"address":"0xdead"}"#
        );
        let decoded: AssetId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, asset);
    }
}
