//! Fail-closed Trading Core startup (remediation D6).
//!
//! The binary never enables trading by default. It strictly parses
//! `TRADING_ENABLED` (case-exact `"true"` / `"false"`; absent disables; anything
//! else is a startup error), and it never reads a credential value or opens a
//! socket.
//!
//! Outcomes:
//! - **disabled** (the default): the fail-closed live composition is assembled to
//!   validate the production path, and startup succeeds read-only.
//! - **enabled but adapters/credentials absent**: startup refuses
//!   ([`StartupError::LiveAdaptersUnavailable`]).
//! - **enabled with the adapter environment present**: this foundation binary
//!   still refuses ([`StartupError::LiveWiringNotComposed`]) because concrete
//!   transports must be injected by the deployment through
//!   `trading_core::live::build_live_relay`; it must not pretend to be live.

use std::process::ExitCode;

use market_types::Bps;
use policy::{PolicyLimits, UsdMicros};
use trading_core::composition::build_policy;
use trading_core::live;

/// Startup refusal reasons. Messages are static and reveal no configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupError {
    /// `TRADING_ENABLED` was neither absent, `"true"`, nor `"false"`.
    InvalidTradingEnabled,
    /// Trading was enabled but the required adapter/credential endpoints are
    /// missing.
    LiveAdaptersUnavailable,
    /// Trading was enabled and configured, but this binary does not inject real
    /// transports; the deployment must compose them explicitly.
    LiveWiringNotComposed,
}

fn limits() -> Option<PolicyLimits> {
    Some(PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).ok()?,
        max_sell_tax: Bps::new(500).ok()?,
        max_price_impact: Bps::new(300).ok()?,
        max_slippage: Bps::new(200).ok()?,
        allowed_chains: std::collections::HashSet::from([chain_types::ChainId::Base]),
        allowed_venues: std::collections::HashSet::from(["uniswap".to_string()]),
    })
}

/// Runs the fail-closed startup decision.
///
/// `live_ready` is presence-only (see [`live::live_env_ready`]); no value is
/// logged or used beyond this decision.
fn startup(trading_enabled: Option<&str>, live_ready: bool) -> Result<(), StartupError> {
    let limits = limits().ok_or(StartupError::InvalidTradingEnabled)?;
    let policy =
        build_policy(trading_enabled, limits).map_err(|_| StartupError::InvalidTradingEnabled)?;
    if !policy.is_trading_enabled() {
        // Validate the production composition path without enabling it.
        let _ = live::build_fail_closed_live_relay(policy);
        return Ok(());
    }
    if !live_ready {
        return Err(StartupError::LiveAdaptersUnavailable);
    }
    Err(StartupError::LiveWiringNotComposed)
}

fn main() -> ExitCode {
    let trading_enabled = std::env::var("TRADING_ENABLED").ok();
    let live_ready = live::live_env_ready(|name| std::env::var(name).ok());
    match startup(trading_enabled.as_deref(), live_ready) {
        Ok(()) => ExitCode::SUCCESS,
        Err(StartupError::InvalidTradingEnabled) => {
            eprintln!("trading-core: invalid TRADING_ENABLED; refusing to start");
            ExitCode::from(2)
        }
        Err(StartupError::LiveAdaptersUnavailable) => {
            eprintln!("trading-core: live adapters/credentials unavailable; fail-closed");
            ExitCode::from(3)
        }
        Err(StartupError::LiveWiringNotComposed) => {
            eprintln!(
                "trading-core: live transports are not composed in this binary; inject them via live::build_live_relay"
            );
            ExitCode::from(4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_startup_is_read_only_success() {
        assert_eq!(startup(None, false), Ok(()));
        assert_eq!(startup(Some("false"), false), Ok(()));
    }

    #[test]
    fn invalid_trading_enabled_refuses() {
        assert_eq!(
            startup(Some("TRUE"), false),
            Err(StartupError::InvalidTradingEnabled)
        );
        assert_eq!(
            startup(Some("1"), false),
            Err(StartupError::InvalidTradingEnabled)
        );
        assert_eq!(
            startup(Some(""), false),
            Err(StartupError::InvalidTradingEnabled)
        );
    }

    #[test]
    fn enabled_without_adapters_fails_closed() {
        assert_eq!(
            startup(Some("true"), false),
            Err(StartupError::LiveAdaptersUnavailable)
        );
    }

    #[test]
    fn enabled_with_adapters_still_requires_explicit_composition() {
        assert_eq!(
            startup(Some("true"), true),
            Err(StartupError::LiveWiringNotComposed)
        );
    }
}
