//! Real MCP stdio binary (P78 composition root).
//!
//! Unlike the fail-closed `mcp-server` placeholder binary, this one runs over
//! the real [`trading_core::composition`] root: the composed agent backend, the
//! recording registry, and the trusted MCP capability context.
//!
//! It strictly parses `TRADING_ENABLED`: only the case-exact `"true"` enables
//! trading, `"false"`/absent disables it, and any other value refuses to start
//! (`ExitCode::FAILURE`). The durable store and order-key provider are the local
//! fail-closed defaults, so no credentials, key material, or network are needed
//! to start; reads and the read-only reconcile path stay available, and every
//! mutation is denied before any port call while disabled.
//!
//! It also strictly parses `RECONCILE_INTERVAL_MS` (absent/`"0"` disables the
//! loop; invalid/non-Unicode refuses startup). When set, the read-only reconcile
//! loop runs for the lifetime of the stdio session and is stopped promptly when
//! `StdioServer::run` returns on EOF or a transport error.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::Arc;

use agent_backend::SystemClock;
use chain_types::ChainId;
use domain::{RiskConstraints, UserId, WalletRef};
use limit_engine::UnavailableOrderKeyProvider;
use market_types::{AtomicAmount, Bps};
use mcp_server::{McpServer, StdioLimits, StdioServer};
use policy::{PolicyLimits, UsdMicros};
use tokio::io::BufReader;
use tokio::sync::watch;
use trading_core::composition::{
    build_capabilities, build_policy, CompositionConfig, MarketReconcileLoop,
    RecordingAgentBackend, TradingCore, TradingCoreSeams, UnavailableOpaqueStore,
};
use trading_core::service::{
    parse_reconcile_interval_ms, spawn_reconcile_loop, RECONCILE_SCHEDULE,
};

/// Fixed frame bound: 1 MiB per frame, unlimited frame count.
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_FRAMES: u64 = 0;

#[tokio::main]
async fn main() -> ExitCode {
    let trading_enabled = match std::env::var("TRADING_ENABLED") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        // A non-Unicode value is not a recognized gate value: refuse to start.
        Err(std::env::VarError::NotUnicode(_)) => return ExitCode::FAILURE,
    };
    let reconcile_interval = match std::env::var("RECONCILE_INTERVAL_MS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        // A non-Unicode interval is not a recognized value: refuse to start.
        Err(std::env::VarError::NotUnicode(_)) => return ExitCode::FAILURE,
    };
    run(trading_enabled.as_deref(), reconcile_interval.as_deref()).await
}

/// Builds the composition root and serves MCP over stdin/stdout.
async fn run(trading_enabled: Option<&str>, reconcile_interval: Option<&str>) -> ExitCode {
    // Strict parse first: an invalid/non-Unicode interval refuses startup before
    // any port is built. Absent or `"0"` leaves the read-only loop off.
    let interval = match parse_reconcile_interval_ms(reconcile_interval) {
        Ok(interval) => interval,
        Err(_) => return ExitCode::FAILURE,
    };
    let limits = match policy_limits() {
        Some(limits) => limits,
        None => return ExitCode::FAILURE,
    };
    let policy = match build_policy(trading_enabled, limits) {
        Ok(policy) => policy,
        Err(_) => return ExitCode::FAILURE,
    };
    let config = match config() {
        Some(config) => config,
        None => return ExitCode::FAILURE,
    };
    let capabilities = build_capabilities(&policy, &config);
    let core = TradingCore::new(
        config,
        policy,
        Arc::new(UnavailableOpaqueStore),
        Arc::new(UnavailableOrderKeyProvider),
        Arc::new(SystemClock),
        TradingCoreSeams::default(),
    );
    let recording = RecordingAgentBackend::new(core.backend(), core.registry());
    let server = McpServer::new(recording, capabilities);
    let stdio = StdioServer::new(
        server,
        StdioLimits {
            max_frame_bytes: MAX_FRAME_BYTES,
            max_frames: MAX_FRAMES,
        },
    );

    // The loop is read-only and off by default; it is spawned only when an
    // interval is configured.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reconcile_task = interval.map(|interval| {
        let reconcile =
            MarketReconcileLoop::new(core.backend(), core.registry(), RECONCILE_SCHEDULE);
        spawn_reconcile_loop(reconcile, interval, shutdown_rx)
    });

    let reader = BufReader::new(tokio::io::stdin());
    let writer = tokio::io::stdout();
    let result = stdio.run(reader, writer).await;
    // `stdio.run` returns on EOF or a transport error: stop the loop promptly
    // and wait for it before reporting the transport result.
    if let Some(task) = reconcile_task {
        let _ = shutdown_tx.send(true);
        let _ = task.await;
    }
    match result {
        Ok(_processed) => ExitCode::SUCCESS,
        Err(_transport) => ExitCode::FAILURE,
    }
}

/// Minimal positive policy limits: one allowed chain, no venue restriction.
fn policy_limits() -> Option<PolicyLimits> {
    Some(PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).ok()?,
        max_sell_tax: Bps::new(500).ok()?,
        max_price_impact: Bps::new(300).ok()?,
        max_slippage: Bps::new(200).ok()?,
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::new(),
    })
}

/// Minimal positive owner/wallet configuration bound to Base.
fn config() -> Option<CompositionConfig> {
    Some(CompositionConfig {
        owner: UserId::new("local-operator").ok()?,
        wallet_ref: WalletRef::new("local-wallet").ok()?,
        chain: ChainId::Base,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).ok()?,
            max_sell_tax: Bps::new(500).ok()?,
            max_price_impact: Bps::new(300).ok()?,
            max_slippage: Bps::new(200).ok()?,
            max_total_cost: None,
        },
        min_fill: AtomicAmount::new(1),
        allowed_chains: HashSet::from([ChainId::Base]),
        max_trade_usd: 1_000_000,
    })
}
