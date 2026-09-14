//! P53 acceptance tests for the channel-agnostic agent command core.

use std::collections::HashSet;

use agent_commands::{
    authorize, AgentCapabilities, AgentChannel, AgentCommand, AgentCommandError, AmountSpec,
    AssetRef, AuthorizedCommand, ChartWindow, DenyReason, LimitPriceSpec, ReadCommand,
    RouterSource, TradeCommand,
};
use chain_types::ChainId;
use domain::TradeSide;

const SOL: &str =
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"}"#;
const USDC: &str =
    r#"{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}"#;
const BASE_TOKEN: &str =
    r#"{"chain":{"kind":"base"},"address":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"}"#;

const PREVIEW_JSON: &str = concat!(
    r#"{"tool":"preview_market_order","token_in":"#,
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
    r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    r#""side":"buy","amount":{"unit":"usd_micros","value":1000000},"#,
    r#""max_slippage_bps":100,"max_price_impact_bps":200}"#
);

const EXECUTE_JSON: &str = concat!(
    r#"{"tool":"execute_market_order","token_in":"#,
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
    r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    r#""side":"buy","amount":{"unit":"usd_micros","value":1000000},"#,
    r#""max_slippage_bps":100,"max_price_impact_bps":200}"#
);

const PLACE_JSON: &str = concat!(
    r#"{"tool":"place_limit_order","token_in":"#,
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
    r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    r#""side":"sell","amount":{"unit":"stablecoin_atomic","value":5000},"#,
    r#""limit_price":{"numerator_atomic":3,"denominator_atomic":2},"#,
    r#""allow_partial_fill":true,"expires_at_ms":1700000000000}"#
);

const CANCEL_JSON: &str = r#"{"tool":"cancel_order","order_id":"order-123"}"#;

const READ_JSONS: &[&str] = &[
    r#"{"tool":"search_token","query":"bonk"}"#,
    r#"{"tool":"get_token","token":{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"}}"#,
    r#"{"tool":"get_chart","token":{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"window":"h1"}"#,
    r#"{"tool":"get_intelligence","token":{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"}}"#,
    r#"{"tool":"get_quote","token_in":{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"amount":{"unit":"token_atomic","value":1000}}"#,
    r#"{"tool":"get_orders","status":"open"}"#,
    r#"{"tool":"get_orders"}"#,
    r#"{"tool":"get_portfolio"}"#,
];

fn caps(trading_enabled: bool) -> AgentCapabilities {
    let mut allowed_chains = HashSet::new();
    allowed_chains.insert(ChainId::Solana);
    AgentCapabilities::new(trading_enabled, allowed_chains, 1_000_000)
}

fn parse(json: &str) -> AgentCommand {
    AgentCommand::parse(json)
        .unwrap_or_else(|error| panic!("command {json} should parse: {error:?}"))
}

fn sol() -> AssetRef {
    AssetRef::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .expect("valid sol asset")
}

fn usdc() -> AssetRef {
    AssetRef::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .expect("valid usdc asset")
}

// --- AC-1 / read availability -------------------------------------------------

#[test]
fn every_read_tool_decodes_and_authorizes_for_both_channels_while_disabled() {
    let disabled = caps(false);
    for json in READ_JSONS {
        let command = parse(json);
        assert!(!command.is_mutating());
        for channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
            let outcome = authorize(channel, command.clone(), &disabled, None);
            assert!(
                matches!(outcome, AuthorizedCommand::Read(_)),
                "read tool {json} should authorize while trading is disabled"
            );
        }
    }
}

#[test]
fn preview_is_the_only_trade_command_allowed_while_disabled() {
    let disabled = caps(false);
    let preview = parse(PREVIEW_JSON);
    assert!(!preview.is_mutating());
    for channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
        assert!(matches!(
            authorize(channel, preview.clone(), &disabled, None),
            AuthorizedCommand::Trade(TradeCommand::PreviewMarketOrder { .. })
        ));
    }

    for (json, expected_mutating) in [
        (EXECUTE_JSON, true),
        (PLACE_JSON, true),
        (CANCEL_JSON, true),
    ] {
        let command = parse(json);
        assert_eq!(command.is_mutating(), expected_mutating);
        for channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
            assert_eq!(
                authorize(channel, command.clone(), &disabled, Some(1)),
                AuthorizedCommand::Denied(DenyReason::TradingDisabled),
                "mutating tool {json} must be denied while disabled"
            );
        }
    }
}

#[test]
fn all_trade_tools_authorize_when_enabled_and_within_limits() {
    let enabled = caps(true);
    for json in [PREVIEW_JSON, EXECUTE_JSON, PLACE_JSON, CANCEL_JSON] {
        let command = parse(json);
        for channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
            assert!(
                matches!(
                    authorize(channel, command.clone(), &enabled, Some(999_999)),
                    AuthorizedCommand::Trade(_)
                ),
                "trade tool {json} should authorize when enabled and within limits"
            );
        }
    }
}

// --- AC-2 ambiguity fails closed ---------------------------------------------

#[test]
fn amount_without_unit_fails_closed() {
    let json = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"value":100}}"#
    );
    assert_eq!(
        AgentCommand::parse(json),
        Err(AgentCommandError::MissingUnit)
    );
}

#[test]
fn bare_amount_fails_closed() {
    let json = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":100}"#
    );
    assert_eq!(AgentCommand::parse(json), Err(AgentCommandError::Malformed));
}

#[test]
fn amount_decoding_is_member_order_independent() {
    let prefix = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    );
    let unit_first = format!("{prefix}\"amount\":{{\"unit\":\"token_atomic\",\"value\":1000}}}}");
    let value_first = format!("{prefix}\"amount\":{{\"value\":1000,\"unit\":\"token_atomic\"}}}}");
    assert_eq!(parse(&unit_first), parse(&value_first));

    // `u128::MAX` in `value`-first order must stay lossless, not fail or truncate.
    let big_value_first = format!(
        "{prefix}\"amount\":{{\"value\":340282366920938463463374607431768211455,\"unit\":\"token_atomic\"}}}}"
    );
    assert_eq!(
        parse(&big_value_first),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::TokenAtomic(u128::MAX),
            router: RouterSource::Okx,
        })
    );

    // The other explicit units are order-independent too.
    let stablecoin_value_first =
        format!("{prefix}\"amount\":{{\"value\":5000,\"unit\":\"stablecoin_atomic\"}}}}");
    assert_eq!(
        parse(&stablecoin_value_first),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::StablecoinAtomic(5000),
            router: RouterSource::Okx,
        })
    );
    let usd_value_first =
        format!("{prefix}\"amount\":{{\"value\":1234,\"unit\":\"usd_micros\"}}}}");
    assert_eq!(
        parse(&usd_value_first),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::UsdMicros(1234),
            router: RouterSource::Okx,
        })
    );

    // Value-first overflow and unknown units still fail closed.
    let overflow_value_first = format!(
        "{prefix}\"amount\":{{\"value\":340282366920938463463374607431768211456,\"unit\":\"token_atomic\"}}}}"
    );
    assert_eq!(
        AgentCommand::parse(&overflow_value_first),
        Err(AgentCommandError::InvalidAmount)
    );
    let unknown_unit_value_first =
        format!("{prefix}\"amount\":{{\"value\":1,\"unit\":\"liters\"}}}}");
    assert_eq!(
        AgentCommand::parse(&unknown_unit_value_first),
        Err(AgentCommandError::InvalidAmount)
    );

    // Direct `AmountSpec` decoding is order-independent as well.
    let direct: AmountSpec =
        serde_json::from_str(r#"{"value":42,"unit":"stablecoin_atomic"}"#).expect("direct decode");
    assert_eq!(direct, AmountSpec::StablecoinAtomic(42));
    let direct_big: AmountSpec = serde_json::from_str(
        r#"{"value":340282366920938463463374607431768211455,"unit":"token_atomic"}"#,
    )
    .expect("direct decode big");
    assert_eq!(direct_big, AmountSpec::TokenAtomic(u128::MAX));
}

#[test]
fn unit_without_value_is_ambiguous() {
    let json = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"unit":"usd_micros"}}"#
    );
    assert_eq!(
        AgentCommand::parse(json),
        Err(AgentCommandError::AmbiguousAmount)
    );
}

#[test]
fn unknown_fields_fail_closed() {
    let json = r#"{"tool":"get_portfolio","extra":"smuggled"}"#;
    assert_eq!(AgentCommand::parse(json), Err(AgentCommandError::Malformed));
}

#[test]
fn inconsistent_outer_command_tag_fails_closed() {
    let json = r#"{"command":"trade","tool":"get_portfolio"}"#;
    assert_eq!(AgentCommand::parse(json), Err(AgentCommandError::Malformed));
    let json = r#"{"command":"read","tool":"cancel_order","order_id":"abc"}"#;
    assert_eq!(AgentCommand::parse(json), Err(AgentCommandError::Malformed));
}

#[test]
fn duplicate_keys_fail_closed() {
    let base = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    );

    // A repeated `unit` must not let the last value silently win.
    let duplicate_unit = format!(
        "{base}\"amount\":{{\"unit\":\"token_atomic\",\"value\":1,\"unit\":\"usd_micros\"}}}}"
    );
    assert_eq!(
        AgentCommand::parse(&duplicate_unit),
        Err(AgentCommandError::Malformed)
    );

    // A repeated `value` is equally ambiguous.
    let duplicate_value =
        format!("{base}\"amount\":{{\"unit\":\"token_atomic\",\"value\":1,\"value\":2}}}}");
    assert_eq!(
        AgentCommand::parse(&duplicate_value),
        Err(AgentCommandError::Malformed)
    );

    // A repeated top-level `tool` must not let `get_portfolio` win.
    let json = r#"{"tool":"withdraw","tool":"get_portfolio"}"#;
    assert_eq!(AgentCommand::parse(json), Err(AgentCommandError::Malformed));

    // The direct typed decoders reject the same ambiguity.
    assert!(serde_json::from_str::<AmountSpec>(
        r#"{"unit":"token_atomic","value":1,"unit":"usd_micros"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<AssetRef>(
        r#"{"chain":{"kind":"solana"},"address":"0xabc","address":"0xdef"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<LimitPriceSpec>(
        r#"{"numerator_atomic":1,"numerator_atomic":2,"denominator_atomic":1}"#
    )
    .is_err());
}

// --- AC-3 forbidden surface ---------------------------------------------------

#[test]
fn forbidden_operations_return_forbidden_not_unknown() {
    let forbidden = [
        "withdraw",
        "withdraw_all",
        "transfer",
        "transfer_token",
        "send",
        "set_owner",
        "set_wallet_owner",
        "change_owner",
        "raise_limit",
        "raise_security_limit",
        "set_limit",
        "sign",
        "sign_raw",
        "sign_transaction",
        "sign_message",
        "export_key",
        "export_private_key",
        "get_private_key",
        "frobnicate",
    ];
    for name in forbidden {
        let json = format!(r#"{{"tool":"{name}"}}"#);
        // Both channels share this parse; assert it for each explicitly.
        for _channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
            assert_eq!(
                AgentCommand::parse(&json),
                Err(AgentCommandError::ForbiddenOperation),
                "{name} must be forbidden, never UnknownTool or a generic parse error"
            );
        }
        assert_ne!(
            AgentCommand::parse(&json),
            Err(AgentCommandError::UnknownTool)
        );
    }
}

// --- chain / notional gating --------------------------------------------------

#[test]
fn disallowed_chain_is_denied() {
    let json = concat!(
        r#"{"tool":"execute_market_order","token_in":"#,
        r#"{"chain":{"kind":"base"},"address":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"},"#,
        r#""token_out":{"chain":{"kind":"base"},"address":"0x4200000000000000000000000000000000000006"},"#,
        r#""side":"buy","amount":{"unit":"usd_micros","value":1000}}"#
    );
    let command = parse(json);
    let caps = caps(true); // only Solana allowed
    for channel in [AgentChannel::Mcp, AgentChannel::Telegram] {
        assert_eq!(
            authorize(channel, command.clone(), &caps, Some(1000)),
            AuthorizedCommand::Denied(DenyReason::ChainNotAllowed)
        );
    }

    // `allowed_chains` is the wallet's *tradable* set: reads remain available
    // even when the referenced chain is not tradable.
    let read = parse(&format!(r#"{{"tool":"get_token","token":{BASE_TOKEN}}}"#));
    assert!(matches!(
        authorize(AgentChannel::Mcp, read, &caps, None),
        AuthorizedCommand::Read(_)
    ));
}

#[test]
fn notional_above_limit_or_missing_valuation_is_denied() {
    let enabled = caps(true);
    let command = parse(EXECUTE_JSON);

    assert_eq!(
        authorize(
            AgentChannel::Mcp,
            command.clone(),
            &enabled,
            Some(1_000_001)
        ),
        AuthorizedCommand::Denied(DenyReason::NotionalExceedsLimit)
    );
    assert_eq!(
        authorize(AgentChannel::Mcp, command.clone(), &enabled, None),
        AuthorizedCommand::Denied(DenyReason::NotionalExceedsLimit)
    );
    // Boundary is inclusive.
    assert!(matches!(
        authorize(AgentChannel::Mcp, command, &enabled, Some(1_000_000)),
        AuthorizedCommand::Trade(_)
    ));

    // A mutating command with no amount still requires a trusted valuation.
    let cancel = parse(CANCEL_JSON);
    assert!(cancel.is_mutating());
    assert_eq!(
        authorize(AgentChannel::Mcp, cancel.clone(), &enabled, None),
        AuthorizedCommand::Denied(DenyReason::NotionalExceedsLimit)
    );
}

#[test]
fn preview_is_not_subject_to_notional_gating() {
    let enabled = caps(true);
    let preview = parse(PREVIEW_JSON);
    assert!(matches!(
        authorize(AgentChannel::Telegram, preview, &enabled, None),
        AuthorizedCommand::Trade(TradeCommand::PreviewMarketOrder { .. })
    ));
}

// --- validation errors --------------------------------------------------------

#[test]
fn invalid_limit_prices_are_rejected() {
    let cases = [
        // Zero numerator.
        concat!(
            r#"{"tool":"place_limit_order","token_in":"#,
            r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
            r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
            r#""side":"sell","amount":{"unit":"token_atomic","value":5},"#,
            r#""limit_price":{"numerator_atomic":0,"denominator_atomic":1},"#,
            r#""allow_partial_fill":false,"expires_at_ms":1}"#
        ),
        // Zero denominator.
        concat!(
            r#"{"tool":"place_limit_order","token_in":"#,
            r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
            r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
            r#""side":"sell","amount":{"unit":"token_atomic","value":5},"#,
            r#""limit_price":{"numerator_atomic":1,"denominator_atomic":0},"#,
            r#""allow_partial_fill":false,"expires_at_ms":1}"#
        ),
        // Overflow above u128::MAX.
        concat!(
            r#"{"tool":"place_limit_order","token_in":"#,
            r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
            r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
            r#""side":"sell","amount":{"unit":"token_atomic","value":5},"#,
            r#""limit_price":{"numerator_atomic":340282366920938463463374607431768211456,"denominator_atomic":1},"#,
            r#""allow_partial_fill":false,"expires_at_ms":1}"#
        ),
        // Missing limit price.
        concat!(
            r#"{"tool":"place_limit_order","token_in":"#,
            r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
            r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
            r#""side":"sell","amount":{"unit":"token_atomic","value":5},"#,
            r#""allow_partial_fill":false,"expires_at_ms":1}"#
        ),
    ];
    for json in cases {
        assert_eq!(
            AgentCommand::parse(json),
            Err(AgentCommandError::InvalidLimitPrice),
            "case should be InvalidLimitPrice"
        );
    }
}

#[test]
fn invalid_assets_are_rejected() {
    let empty = r#"{"tool":"get_token","token":{"chain":{"kind":"solana"},"address":"  "}}"#;
    assert_eq!(
        AgentCommand::parse(empty),
        Err(AgentCommandError::InvalidAsset)
    );

    let oversized = format!(
        r#"{{"tool":"get_token","token":{{"chain":{{"kind":"solana"}},"address":"{}"}}}}"#,
        "A".repeat(200)
    );
    assert_eq!(
        AgentCommand::parse(&oversized),
        Err(AgentCommandError::InvalidAsset)
    );

    let blank_custom_chain =
        r#"{"tool":"get_token","token":{"chain":{"kind":"other","value":""},"address":"0xabc"}}"#;
    assert_eq!(
        AgentCommand::parse(blank_custom_chain),
        Err(AgentCommandError::InvalidAsset)
    );

    let unknown_chain =
        r#"{"tool":"get_token","token":{"chain":{"kind":"nope"},"address":"0xabc"}}"#;
    assert_eq!(
        AgentCommand::parse(unknown_chain),
        Err(AgentCommandError::InvalidAsset)
    );
}

#[test]
fn invalid_windows_are_rejected() {
    let json = concat!(
        r#"{"tool":"get_chart","token":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""window":"m7"}"#
    );
    assert_eq!(
        AgentCommand::parse(json),
        Err(AgentCommandError::InvalidWindow)
    );
}

#[test]
fn zero_and_overflowing_amounts_are_rejected() {
    let zero = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"unit":"token_atomic","value":0}}"#
    );
    assert_eq!(
        AgentCommand::parse(zero),
        Err(AgentCommandError::InvalidAmount)
    );

    let overflow = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"unit":"token_atomic","value":340282366920938463463374607431768211456}}"#
    );
    assert_eq!(
        AgentCommand::parse(overflow),
        Err(AgentCommandError::InvalidAmount)
    );

    let unknown_unit = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"unit":"liters","value":1}}"#
    );
    assert_eq!(
        AgentCommand::parse(unknown_unit),
        Err(AgentCommandError::InvalidAmount)
    );
}

// --- AC-4 channel parity ------------------------------------------------------

#[test]
fn both_channels_share_identical_authorization_rules() {
    let valuations = [
        None,
        Some(0),
        Some(999_999),
        Some(1_000_000),
        Some(1_000_001),
    ];
    let commands = [
        READ_JSONS[0],
        READ_JSONS[4],
        READ_JSONS[6],
        PREVIEW_JSON,
        EXECUTE_JSON,
        PLACE_JSON,
        CANCEL_JSON,
    ];
    for enabled in [false, true] {
        let capabilities = caps(enabled);
        for json in commands {
            let command = parse(json);
            for valuation in valuations {
                let mcp = authorize(AgentChannel::Mcp, command.clone(), &capabilities, valuation);
                let telegram = authorize(
                    AgentChannel::Telegram,
                    command.clone(),
                    &capabilities,
                    valuation,
                );
                assert_eq!(mcp, telegram, "channels diverged for {json}");
            }
        }
    }
}

// --- AC-5 redaction -----------------------------------------------------------

#[test]
fn errors_and_debug_never_echo_request_values() {
    let address_secret = "SECRETADDRESS".repeat(12);
    let cases = vec![
        (
            format!(
                r#"{{"tool":"get_quote","token_in":{SOL},"token_out":{USDC},"amount":{{"value":9876543210123456789}}}}"#
            ),
            vec!["9876543210123456789", "So11111111111111111111111111111111111111112"],
        ),
        (
            format!(
                r#"{{"tool":"get_quote","token_in":{SOL},"token_out":{USDC},"amount":9876543210123456789}}"#
            ),
            vec!["9876543210123456789", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"],
        ),
        (
            r#"{"tool":"get_portfolio","query":"QUERYSECRETVALUE"}"#.to_string(),
            vec!["QUERYSECRETVALUE"],
        ),
        (
            format!(
                r#"{{"tool":"get_token","token":{{"chain":{{"kind":"solana"}},"address":"{address_secret}"}}}}"#
            ),
            vec![address_secret.as_str()],
        ),
        (
            format!(r#"{{"tool":"get_chart","token":{SOL},"window":"WINDOWSECRET"}}"#),
            vec!["WINDOWSECRET"],
        ),
        (
            format!(
                r#"{{"tool":"get_quote","token_in":{SOL},"token_out":{USDC},"amount":{{"unit":"SECRETUNIT","value":1}}}}"#
            ),
            vec!["SECRETUNIT"],
        ),
        (
            concat!(
                r#"{"tool":"place_limit_order","token_in":"#,
                r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
                r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
                r#""side":"sell","amount":{"unit":"token_atomic","value":5},"#,
                r#""limit_price":{"numerator_atomic":123456789012345678901,"denominator_atomic":0},"#,
                r#""allow_partial_fill":false,"expires_at_ms":1}"#
            )
            .to_string(),
            vec!["123456789012345678901"],
        ),
    ];

    for (json, secrets) in cases {
        let error = AgentCommand::parse(&json).expect_err("case must fail");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for secret in secrets {
            assert!(
                !display.contains(secret),
                "Display leaked {secret}: {display}"
            );
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
    }
}

#[test]
fn capability_debug_redacts_chain_identities() {
    let capabilities = caps(true);
    let debug = format!("{capabilities:?}");
    assert!(!debug.contains("solana"));
    assert!(debug.contains("allowed_chains"));
}

#[test]
fn authorized_command_debug_redacts_payload() {
    let outcome = authorize(
        AgentChannel::Mcp,
        parse(EXECUTE_JSON),
        &caps(true),
        Some(999_999),
    );
    let debug = format!("{outcome:?}");
    assert!(!debug.contains("1000000"));
    assert!(!debug.contains("So11111111111111111111111111111111111111112"));
    assert!(!debug.contains("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
}

#[test]
fn command_debug_is_payload_free() {
    let query = "SECRETQUERY123";
    let order_id = "SECRETORDERID456";
    let amount_atomic = 9876543210123456789u128;

    let read_query = parse(&format!(r#"{{"tool":"search_token","query":"{query}"}}"#));
    let read_quote = parse(&format!(
        r#"{{"tool":"get_quote","token_in":{SOL},"token_out":{USDC},"amount":{{"unit":"token_atomic","value":{amount_atomic}}}}}"#
    ));
    let trade_cancel = parse(&format!(
        r#"{{"tool":"cancel_order","order_id":"{order_id}"}}"#
    ));
    let trade_place = parse(PLACE_JSON);

    let asset = sol();
    let amount = AmountSpec::TokenAtomic(amount_atomic);
    let limit_price = LimitPriceSpec::new(123456789012345678901u128, 2).expect("valid price");

    let rendered = [
        format!("{read_query:?}"),
        format!("{read_quote:?}"),
        format!("{trade_cancel:?}"),
        format!("{trade_place:?}"),
        format!("{asset:?}"),
        format!("{amount:?}"),
        format!("{limit_price:?}"),
    ];

    let secrets = [
        query,
        order_id,
        "9876543210123456789",
        "123456789012345678901",
        "So11111111111111111111111111111111111111112",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    ];
    for text in &rendered {
        for secret in secrets {
            assert!(!text.contains(secret), "Debug leaked {secret}: {text}");
        }
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "Debug leaked an ASCII digit: {text}"
        );
    }
}

fn assert_failure_is_payload_free<T>(input: &str, secrets: &[&str])
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    let error = serde_json::from_str::<T>(input)
        .map(|value| format!("{value:?}"))
        .expect_err("input must fail to deserialize");
    let display = error.to_string();
    let debug = format!("{error:?}");
    for secret in secrets {
        assert!(
            !display.contains(secret),
            "Display leaked {secret}: {display}"
        );
        assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
    }
}

#[test]
fn direct_deserialize_failures_are_payload_free() {
    let bare_amount = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":9876543210123456789}"#
    );
    let wrong_case_unit = concat!(
        r#"{"tool":"get_quote","token_in":"#,
        r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
        r#""amount":{"unit":"TOKEN_ATOMIC","value":12345}}"#
    );
    let forbidden_tool = r#"{"tool":"withdraw","order_id":"SECRETORDER789"}"#;
    let bad_asset = concat!(
        r#"{"tool":"get_token","token":"#,
        r#"{"chain":{"kind":"solana"},"address":"SECRET ADDRESS 42"}}"#
    );
    let bad_asset_direct = r#"{"chain":{"kind":"solana"},"address":"SECRET ADDRESS 42"}"#;

    let secrets = [
        "SECRET",
        "SECRETQUERY123",
        "9876543210123456789",
        "SECRETORDER789",
    ];
    let inputs = [
        r#""SECRETQUERY123""#,
        "9876543210123456789",
        "[1,2,3]",
        bare_amount,
        wrong_case_unit,
        forbidden_tool,
        bad_asset,
        bad_asset_direct,
    ];

    for input in inputs {
        assert_failure_is_payload_free::<AgentCommand>(input, &secrets);
        assert_failure_is_payload_free::<ReadCommand>(input, &secrets);
        assert_failure_is_payload_free::<TradeCommand>(input, &secrets);
        assert_failure_is_payload_free::<AmountSpec>(input, &secrets);
        assert_failure_is_payload_free::<AssetRef>(input, &secrets);
        assert_failure_is_payload_free::<LimitPriceSpec>(input, &secrets);
    }
}

// --- serialization round trips ------------------------------------------------

fn all_commands() -> Vec<AgentCommand> {
    vec![
        AgentCommand::Read(ReadCommand::SearchToken {
            query: "bonk".to_string(),
        }),
        AgentCommand::Read(ReadCommand::GetToken { token: sol() }),
        AgentCommand::Read(ReadCommand::GetChart {
            token: sol(),
            window: ChartWindow::M5,
        }),
        AgentCommand::Read(ReadCommand::GetChart {
            token: sol(),
            window: ChartWindow::M15,
        }),
        AgentCommand::Read(ReadCommand::GetChart {
            token: sol(),
            window: ChartWindow::H1,
        }),
        AgentCommand::Read(ReadCommand::GetChart {
            token: sol(),
            window: ChartWindow::H4,
        }),
        AgentCommand::Read(ReadCommand::GetChart {
            token: sol(),
            window: ChartWindow::D1,
        }),
        AgentCommand::Read(ReadCommand::GetIntelligence { token: sol() }),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::TokenAtomic(u128::MAX),
            router: RouterSource::Okx,
        }),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::StablecoinAtomic(42),
            router: RouterSource::Okx,
        }),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::UsdMicros(u64::MAX),
            router: RouterSource::Okx,
        }),
        AgentCommand::Read(ReadCommand::GetOrders {
            status: Some("open".to_string()),
        }),
        AgentCommand::Read(ReadCommand::GetOrders { status: None }),
        AgentCommand::Read(ReadCommand::GetPortfolio),
        AgentCommand::Trade(TradeCommand::PreviewMarketOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Buy,
            amount: AmountSpec::UsdMicros(1_000_000),
            max_slippage_bps: Some(100),
            max_price_impact_bps: Some(200),
            router: RouterSource::Okx,
        }),
        AgentCommand::Trade(TradeCommand::PreviewMarketOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Sell,
            amount: AmountSpec::TokenAtomic(7),
            max_slippage_bps: None,
            max_price_impact_bps: None,
            router: RouterSource::Okx,
        }),
        AgentCommand::Trade(TradeCommand::ExecuteMarketOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Buy,
            amount: AmountSpec::StablecoinAtomic(5000),
            max_slippage_bps: Some(50),
            max_price_impact_bps: None,
            router: RouterSource::Okx,
        }),
        AgentCommand::Trade(TradeCommand::PlaceLimitOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Sell,
            amount: AmountSpec::TokenAtomic(9),
            limit_price: LimitPriceSpec::new(u128::MAX, u128::MAX - 1).expect("valid price"),
            allow_partial_fill: true,
            expires_at_ms: 1_700_000_000_000,
        }),
        AgentCommand::Trade(TradeCommand::CancelOrder {
            order_id: "order-123".to_string(),
        }),
    ]
}

#[test]
fn every_command_variant_round_trips() {
    for command in all_commands() {
        let json = serde_json::to_string(&command).expect("serialize");
        let via_parse = AgentCommand::parse(&json)
            .unwrap_or_else(|error| panic!("parse failed for {json}: {error:?}"));
        assert_eq!(via_parse, command, "parse round-trip failed for {json}");

        let via_serde: AgentCommand =
            serde_json::from_str(&json).expect("derived deserialize round-trip");
        assert_eq!(via_serde, command, "serde round-trip failed for {json}");
    }
}

#[test]
fn direct_asset_and_price_helpers_convert_to_canonical_types() {
    let asset = sol();
    let canonical = asset.to_asset_id().expect("valid canonical asset");
    assert_eq!(canonical.chain, ChainId::Solana);
    assert_eq!(canonical.address, asset.address);

    let price = LimitPriceSpec::new(3, 2).expect("valid price");
    let ratio = price.to_price_ratio().expect("valid ratio");
    assert_eq!(ratio.numerator_atomic(), 3);
    assert_eq!(ratio.denominator_atomic(), 2);
    assert_eq!(
        LimitPriceSpec::new(0, 1),
        Err(AgentCommandError::InvalidLimitPrice)
    );

    assert_eq!(
        AssetRef::new(ChainId::Solana, "   "),
        Err(AgentCommandError::InvalidAsset)
    );
}

#[test]
fn router_preference_defaults_to_okx_and_is_explicitly_selectable() {
    let explicit_local = AgentCommand::Read(ReadCommand::GetQuote {
        token_in: sol(),
        token_out: usdc(),
        amount: AmountSpec::TokenAtomic(1),
        router: RouterSource::Local,
    });

    // Explicit Local round-trips through serialization and parsing. The wire key
    // is `router_preference`; the Rust field is `router`.
    let local_json = serde_json::to_string(&explicit_local).expect("json");
    assert!(local_json.contains("\"router_preference\":\"local\""));
    assert_eq!(
        AgentCommand::parse(&local_json).expect("parse"),
        explicit_local
    );

    let mut value: serde_json::Value = serde_json::from_str(&local_json).expect("value");

    // An omitted router_preference resolves to OKX (the new-session default).
    let mut omitted = value.clone();
    omitted
        .as_object_mut()
        .expect("object")
        .remove("router_preference");
    assert_eq!(
        AgentCommand::parse(&serde_json::to_string(&omitted).expect("json")).expect("parse"),
        AgentCommand::Read(ReadCommand::GetQuote {
            token_in: sol(),
            token_out: usdc(),
            amount: AmountSpec::TokenAtomic(1),
            router: RouterSource::Okx,
        })
    );

    // An unknown selector fails closed rather than defaulting.
    let mut unknown = value.clone();
    unknown.as_object_mut().expect("object").insert(
        "router_preference".to_string(),
        serde_json::json!("binance"),
    );
    assert_eq!(
        AgentCommand::parse(&serde_json::to_string(&unknown).expect("json")),
        Err(AgentCommandError::Malformed)
    );

    // The legacy `router` spelling is rejected as an unknown key, so there is
    // exactly one accepted wire name.
    let mut legacy = value.clone();
    legacy
        .as_object_mut()
        .expect("object")
        .insert("router".to_string(), serde_json::json!("local"));
    assert_eq!(
        AgentCommand::parse(&serde_json::to_string(&legacy).expect("json")),
        Err(AgentCommandError::Malformed)
    );

    // A duplicate router_preference key fails closed (last-win is never accepted).
    let duplicate = local_json.replace(
        "\"router_preference\":\"local\"",
        "\"router_preference\":\"local\",\"router_preference\":\"okx\"",
    );
    assert_eq!(
        AgentCommand::parse(&duplicate),
        Err(AgentCommandError::Malformed)
    );
    let _ = value
        .as_object_mut()
        .expect("object")
        .remove("router_preference");
    assert_eq!(RouterSource::default(), RouterSource::Okx);
    assert_eq!(RouterSource::Okx.as_str(), "okx");
    assert_eq!(RouterSource::Local.as_str(), "local");
}

#[test]
fn market_order_router_preference_defaults_to_okx_and_is_explicitly_selectable() {
    // An omitted router_preference resolves to OKX for both market-order tools.
    assert_eq!(
        parse(PREVIEW_JSON),
        AgentCommand::Trade(TradeCommand::PreviewMarketOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Buy,
            amount: AmountSpec::UsdMicros(1_000_000),
            max_slippage_bps: Some(100),
            max_price_impact_bps: Some(200),
            router: RouterSource::Okx,
        })
    );
    assert_eq!(
        parse(EXECUTE_JSON),
        AgentCommand::Trade(TradeCommand::ExecuteMarketOrder {
            token_in: sol(),
            token_out: usdc(),
            side: TradeSide::Buy,
            amount: AmountSpec::UsdMicros(1_000_000),
            max_slippage_bps: Some(100),
            max_price_impact_bps: Some(200),
            router: RouterSource::Okx,
        })
    );

    // Explicit local is preserved for both tools, and the wire key round-trips.
    let local_preview = PREVIEW_JSON.replace(
        "\"max_slippage_bps\":100",
        "\"router_preference\":\"local\",\"max_slippage_bps\":100",
    );
    let parsed = parse(&local_preview);
    let AgentCommand::Trade(TradeCommand::PreviewMarketOrder { router, .. }) = parsed else {
        panic!("expected a preview command");
    };
    assert_eq!(router, RouterSource::Local);

    let local_execute = EXECUTE_JSON.replace(
        "\"max_slippage_bps\":100",
        "\"router_preference\":\"local\",\"max_slippage_bps\":100",
    );
    let parsed = parse(&local_execute);
    let AgentCommand::Trade(TradeCommand::ExecuteMarketOrder { router, .. }) = parsed else {
        panic!("expected an execute command");
    };
    assert_eq!(router, RouterSource::Local);
    assert!(serde_json::to_string(&parsed)
        .expect("json")
        .contains("\"router_preference\":\"local\""));
}
