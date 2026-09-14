//! Focused integration tests for the additive P83 DEX adapter boundary.
//!
//! The tests re-derive parity and minimality from the landed `simulation` kernels
//! (never from the adapter code under test), assert both chains/asset binding and
//! pool immutability, and reuse the redaction sentinel style from
//! `negative_security_tests.rs`.

mod common;

use common::*;
use market_types::{AtomicAmount, PoolKindState};
use routing::{
    AdapterRegistry, BinAdapter, ClmmAdapter, CpmmAdapter, DexAdapter, PoolRefLabel, RoutingError,
    MAX_ADAPTERS,
};
use simulation::{
    simulate_bin_exact_input, simulate_bin_exact_output, simulate_clmm_exact_input,
    simulate_clmm_exact_output, simulate_cpmm_exact_input, simulate_cpmm_exact_output,
    BinExactInputRequest, BinExactOutputRequest, BinSimulationError, ClmmExactInputRequest,
    ClmmExactOutputRequest, ClmmSimulationError, CpmmExactInputRequest, CpmmExactOutputRequest,
    CpmmSimulationErrorClass,
};

fn reference() -> PoolRefLabel {
    PoolRefLabel::new("0xpool-adapter").expect("valid pool ref")
}

fn foreign_chain_token() -> chain_types::AssetId {
    solana_asset("So11111111111111111111111111111111111111112")
}

fn cpmm_state() -> PoolKindState {
    PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30))
}

fn clmm_state() -> PoolKindState {
    PoolKindState::Clmm(clmm(usdc(), weth()))
}

fn bin_state() -> PoolKindState {
    PoolKindState::Bin(bin(usdc(), weth()))
}

// --- Exact-in parity vs. the landed kernels -------------------------------

#[test]
fn cpmm_exact_in_parity_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let amount_in = AtomicAmount::new(10_000);
    let state = cpmm_state();

    let quote = registry
        .quote_exact_in(&state, &pool_ref, &usdc(), amount_in)
        .expect("cpmm quote");
    let PoolKindState::Cpmm(pool) = &state else {
        unreachable!("cpmm fixture");
    };
    let direct = simulate_cpmm_exact_input(pool, &CpmmExactInputRequest::new(usdc(), amount_in))
        .expect("cpmm kernel");

    assert_eq!(quote.venue.as_str(), "cpmm");
    assert_eq!(quote.pool_ref.as_str(), pool_ref.as_str());
    assert_eq!(quote.token_in, usdc());
    assert_eq!(quote.token_out, weth());
    assert_eq!(quote.amount_in, amount_in);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.pool_fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert!(quote.impact_bps.is_some());
}

#[test]
fn clmm_exact_in_parity_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let amount_in = AtomicAmount::new(100_000);
    let state = clmm_state();

    let quote = registry
        .quote_exact_in(&state, &pool_ref, &usdc(), amount_in)
        .expect("clmm quote");
    let PoolKindState::Clmm(pool) = &state else {
        unreachable!("clmm fixture");
    };
    let direct = simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: usdc(),
            amount_in,
            token_out: None,
        },
    )
    .expect("clmm kernel");

    assert_eq!(quote.venue.as_str(), "clmm");
    assert_eq!(quote.token_in, usdc());
    assert_eq!(quote.token_out, weth());
    assert_eq!(quote.amount_in, amount_in);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert_eq!(quote.impact_bps, None);
}

#[test]
fn bin_exact_in_parity_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let amount_in = AtomicAmount::new(1_000);
    let state = bin_state();

    let quote = registry
        .quote_exact_in(&state, &pool_ref, &usdc(), amount_in)
        .expect("bin quote");
    let PoolKindState::Bin(pool) = &state else {
        unreachable!("bin fixture");
    };
    let direct = simulate_bin_exact_input(pool, &BinExactInputRequest::new(usdc(), amount_in))
        .expect("bin kernel");

    assert_eq!(quote.venue.as_str(), "bin");
    assert_eq!(quote.token_in, usdc());
    assert_eq!(quote.token_out, weth());
    assert_eq!(quote.amount_in, amount_in);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert_eq!(quote.impact_bps, None);
}

// --- Exact-out parity and proven minimality --------------------------------

#[test]
fn cpmm_exact_out_is_minimal_and_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let state = cpmm_state();
    let PoolKindState::Cpmm(pool) = &state else {
        unreachable!("cpmm fixture");
    };
    let target = simulate_cpmm_exact_input(
        pool,
        &CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000)),
    )
    .expect("target")
    .output
    .amount;

    let quote = registry
        .quote_exact_out(&state, &pool_ref, &usdc(), target)
        .expect("cpmm exact out");
    let direct = simulate_cpmm_exact_output(pool, &CpmmExactOutputRequest::new(usdc(), target))
        .expect("cpmm exact out kernel");

    assert_eq!(quote.amount_in, direct.input.amount);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.pool_fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert!(quote.amount_out.get() >= target.get());
    assert!(quote.impact_bps.is_some());

    let previous = simulate_cpmm_exact_input(
        pool,
        &CpmmExactInputRequest::new(usdc(), AtomicAmount::new(quote.amount_in.get() - 1)),
    )
    .map(|realized| realized.output.amount.get())
    .unwrap_or(0);
    assert!(previous < target.get(), "exact-out input was not minimal");
}

#[test]
fn clmm_exact_out_is_minimal_and_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let state = clmm_state();
    let PoolKindState::Clmm(pool) = &state else {
        unreachable!("clmm fixture");
    };
    let target = simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: usdc(),
            amount_in: AtomicAmount::new(100_000),
            token_out: None,
        },
    )
    .expect("target")
    .output
    .amount;

    let quote = registry
        .quote_exact_out(&state, &pool_ref, &usdc(), target)
        .expect("clmm exact out");
    let direct = simulate_clmm_exact_output(pool, &ClmmExactOutputRequest::new(usdc(), target))
        .expect("clmm exact out kernel");

    assert_eq!(quote.amount_in, direct.input.amount);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert_eq!(quote.impact_bps, None);

    let previous = simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: usdc(),
            amount_in: AtomicAmount::new(quote.amount_in.get() - 1),
            token_out: None,
        },
    )
    .map(|realized| realized.output.amount.get())
    .unwrap_or(0);
    assert!(previous < target.get(), "exact-out input was not minimal");
}

#[test]
fn bin_exact_out_is_minimal_and_matches_kernel() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let state = bin_state();
    let PoolKindState::Bin(pool) = &state else {
        unreachable!("bin fixture");
    };
    let target = simulate_bin_exact_input(
        pool,
        &BinExactInputRequest::new(usdc(), AtomicAmount::new(1_000)),
    )
    .expect("target")
    .output
    .amount;

    let quote = registry
        .quote_exact_out(&state, &pool_ref, &usdc(), target)
        .expect("bin exact out");
    let direct = simulate_bin_exact_output(pool, &BinExactOutputRequest::new(usdc(), target))
        .expect("bin exact out kernel");

    assert_eq!(quote.amount_in, direct.input.amount);
    assert_eq!(quote.amount_out, direct.output.amount);
    assert_eq!(quote.pool_fee, direct.fee);
    assert_eq!(quote.effective_input, direct.effective_input.amount);
    assert_eq!(quote.impact_bps, None);

    let previous = simulate_bin_exact_input(
        pool,
        &BinExactInputRequest::new(usdc(), AtomicAmount::new(quote.amount_in.get() - 1)),
    )
    .map(|realized| realized.output.amount.get())
    .unwrap_or(0);
    assert!(previous < target.get(), "exact-out input was not minimal");
}

// --- Direction / chain binding and pool immutability -----------------------

#[test]
fn cpmm_binding_failures_are_typed_and_immutable() {
    let pool_ref = reference();
    let state = cpmm_state();
    let before = state.clone();

    assert_eq!(
        CpmmAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &another_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Cpmm(
            CpmmSimulationErrorClass::AssetNotFoundInPool
        ))
    );
    assert_eq!(
        CpmmAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &foreign_chain_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Cpmm(CpmmSimulationErrorClass::ChainMismatch))
    );
    assert_eq!(state, before, "pool state must not mutate");
}

#[test]
fn clmm_binding_failures_are_typed_and_immutable() {
    let pool_ref = reference();
    let state = clmm_state();
    let before = state.clone();

    assert_eq!(
        ClmmAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &another_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Clmm(
            ClmmSimulationError::InvalidAssetDirection
        ))
    );
    assert_eq!(
        ClmmAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &foreign_chain_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Clmm(ClmmSimulationError::ChainMismatch))
    );
    assert_eq!(state, before, "pool state must not mutate");
}

#[test]
fn bin_binding_failures_are_typed_and_immutable() {
    let pool_ref = reference();
    let state = bin_state();
    let before = state.clone();

    assert_eq!(
        BinAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &another_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Bin(BinSimulationError::InvalidAssetDirection))
    );
    assert_eq!(
        BinAdapter.quote_exact_in(
            &pool_ref,
            &state,
            &foreign_chain_token(),
            AtomicAmount::new(1_000)
        ),
        Err(RoutingError::Bin(BinSimulationError::ChainMismatch))
    );
    assert_eq!(state, before, "pool state must not mutate");
}

// --- Unsupported kind and registry bounds ----------------------------------

#[test]
fn registry_without_matching_adapter_denies_state() {
    let registry = AdapterRegistry::new(vec![Box::new(CpmmAdapter)]).expect("registry");
    let pool_ref = reference();
    assert_eq!(
        registry.quote_exact_in(&clmm_state(), &pool_ref, &usdc(), AtomicAmount::new(1_000)),
        Err(RoutingError::UnsupportedPoolKind)
    );
    assert_eq!(
        registry.quote_exact_out(&bin_state(), &pool_ref, &usdc(), AtomicAmount::new(1)),
        Err(RoutingError::UnsupportedPoolKind)
    );

    assert!(CpmmAdapter.supports(&cpmm_state()));
    assert!(!CpmmAdapter.supports(&clmm_state()));
    assert!(ClmmAdapter.supports(&clmm_state()));
    assert!(!ClmmAdapter.supports(&bin_state()));
    assert!(BinAdapter.supports(&bin_state()));
    assert!(!BinAdapter.supports(&cpmm_state()));
}

#[test]
fn registry_construction_is_bounded() {
    assert_eq!(
        AdapterRegistry::new(Vec::new()).err(),
        Some(RoutingError::EmptyPoolSet)
    );

    let over_bound: Vec<Box<dyn DexAdapter>> = (0..=MAX_ADAPTERS)
        .map(|_| Box::new(CpmmAdapter) as Box<dyn DexAdapter>)
        .collect();
    assert_eq!(
        AdapterRegistry::new(over_bound).err(),
        Some(RoutingError::BudgetExceeded)
    );

    let duplicates: Vec<Box<dyn DexAdapter>> = vec![Box::new(CpmmAdapter), Box::new(CpmmAdapter)];
    assert_eq!(
        AdapterRegistry::new(duplicates).err(),
        Some(RoutingError::InvalidVenueLabel)
    );

    let distinct: Vec<Box<dyn DexAdapter>> = vec![
        Box::new(CpmmAdapter),
        Box::new(ClmmAdapter),
        Box::new(BinAdapter),
    ];
    assert!(AdapterRegistry::new(distinct).is_ok());
}

// --- Swap instruction floor ------------------------------------------------

#[test]
fn swap_instruction_matches_quote_and_respects_floor() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let quote = registry
        .quote_exact_in(&cpmm_state(), &pool_ref, &usdc(), AtomicAmount::new(10_000))
        .expect("quote");

    let instruction = CpmmAdapter
        .swap_instruction(&quote, quote.amount_out)
        .expect("floor at equality");
    assert_eq!(instruction.venue, quote.venue);
    assert_eq!(instruction.pool_ref, quote.pool_ref);
    assert_eq!(instruction.token_in, quote.token_in);
    assert_eq!(instruction.token_out, quote.token_out);
    assert_eq!(instruction.amount_in, quote.amount_in);
    assert_eq!(instruction.min_amount_out, quote.amount_out);

    let too_high = AtomicAmount::new(quote.amount_out.get() + 1);
    assert_eq!(
        CpmmAdapter.swap_instruction(&quote, too_high),
        Err(RoutingError::MinAmountOutExceedsQuote)
    );

    let clmm_quote = registry
        .quote_exact_in(
            &clmm_state(),
            &pool_ref,
            &usdc(),
            AtomicAmount::new(100_000),
        )
        .expect("clmm quote");
    assert!(ClmmAdapter
        .swap_instruction(&clmm_quote, clmm_quote.amount_out)
        .is_ok());

    let bin_quote = registry
        .quote_exact_in(&bin_state(), &pool_ref, &usdc(), AtomicAmount::new(1_000))
        .expect("bin quote");
    assert!(BinAdapter
        .swap_instruction(&bin_quote, bin_quote.amount_out)
        .is_ok());
}

// --- Determinism -----------------------------------------------------------

#[test]
fn identical_inputs_produce_identical_quotes_and_instructions() {
    let registry = AdapterRegistry::local();
    let pool_ref = reference();
    let cases = [
        (cpmm_state(), usdc(), 10_000u128),
        (clmm_state(), usdc(), 100_000u128),
        (bin_state(), usdc(), 1_000u128),
    ];

    for (state, token_in, amount) in &cases {
        let first = registry
            .quote_exact_in(state, &pool_ref, token_in, AtomicAmount::new(*amount))
            .expect("first exact-in");
        let second = registry
            .quote_exact_in(state, &pool_ref, token_in, AtomicAmount::new(*amount))
            .expect("second exact-in");
        assert_eq!(first, second);

        let first_out = registry
            .quote_exact_out(state, &pool_ref, token_in, first.amount_out)
            .expect("first exact-out");
        let second_out = registry
            .quote_exact_out(state, &pool_ref, token_in, first.amount_out)
            .expect("second exact-out");
        assert_eq!(first_out, second_out);

        let first_swap = CpmmAdapter
            .swap_instruction(&first, first.amount_out)
            .expect("first swap");
        let second_swap = CpmmAdapter
            .swap_instruction(&second, second.amount_out)
            .expect("second swap");
        assert_eq!(first_swap, second_swap);
    }
}

// --- Redaction -------------------------------------------------------------

fn assert_no_payload(text: &str) {
    let mut run = 0usize;
    let mut longest = 0usize;
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(longest < 8, "hex-looking payload leaked: {text}");
    for sentinel in [
        "0xdeadbeefcafebabe",
        "So11111111111111111111111111111111111111112",
        "123456789",
    ] {
        assert!(!text.contains(sentinel), "sentinel leaked: {text}");
    }
}

#[test]
fn adapter_errors_are_redacted() {
    let produced = vec![
        RoutingError::MinAmountOutExceedsQuote,
        RoutingError::UnsupportedPoolKind,
        RoutingError::EmptyPoolSet,
        RoutingError::BudgetExceeded,
        RoutingError::InvalidVenueLabel,
        RoutingError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool),
        RoutingError::Cpmm(CpmmSimulationErrorClass::ChainMismatch),
        RoutingError::Clmm(ClmmSimulationError::InvalidAssetDirection),
        RoutingError::Clmm(ClmmSimulationError::ChainMismatch),
        RoutingError::Bin(BinSimulationError::InvalidAssetDirection),
        RoutingError::Bin(BinSimulationError::ChainMismatch),
    ];
    for error in produced {
        assert_no_payload(&format!("{error}"));
        assert_no_payload(&format!("{error:?}"));
    }

    let pool_ref = reference();
    let live = CpmmAdapter
        .quote_exact_in(
            &pool_ref,
            &cpmm_state(),
            &foreign_chain_token(),
            AtomicAmount::new(1),
        )
        .expect_err("foreign chain must fail");
    assert_no_payload(&format!("{live}"));
    assert_no_payload(&format!("{live:?}"));
}
