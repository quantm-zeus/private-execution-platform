//! Production composition seam for the private API opaque surface (BR-1/BR-3).
//!
//! Two things are genuinely operator-owned and are resolved here from the
//! environment:
//!
//! 1. **`TRADING_ENABLED`** — parsed strictly and case-exactly (`"true"` /
//!    `"false"`; unset disables). Any other value is a startup error so a typo
//!    can never silently enable execution. The parsed gate drives *both* the
//!    advertised bootstrap document and the server-side kill switch, so the
//!    browser and the enforcement layer cannot disagree.
//! 2. **The Trading Core backend** — the concrete `AgentBackend`, authoritative
//!    `AgentCapabilities`, `InstrumentRegistry`, `WebContractBackend` and
//!    realtime `StreamSource` are injected by the operator's composition. Until
//!    they are wired, every mutation returns an authenticated
//!    `capability_missing` denial — never a fabricated success.
//!
//! Crucially, enabling trading alone does **not** advertise or serve any
//! capability the deployment cannot actually provide: the document is derived
//! from what is wired. This is what keeps the advertised capability set
//! authoritative rather than aspirational.

use std::sync::Arc;

use crate::opaque::{
    BootstrapDocument, BootstrapProvider, CapabilitySet, ChainEntry, CommandDispatcher,
    FailClosedDispatcher, OpaqueClock, OpaqueServiceState,
};
use crate::stream::{FailClosedStreamSource, StreamSource};

/// Strictly parsed `TRADING_ENABLED` gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradingGate {
    Enabled,
    Disabled,
}

impl TradingGate {
    /// Parse the raw environment value. `None`/`"false"` disable; `"true"`
    /// enables; anything else (including `"TRUE"`) is invalid.
    pub fn parse(raw: Option<&str>) -> Result<Self, TradingGateError> {
        match raw {
            None | Some("false") => Ok(Self::Disabled),
            Some("true") => Ok(Self::Enabled),
            Some(_) => Err(TradingGateError),
        }
    }

    /// Read `TRADING_ENABLED` from the process environment.
    pub fn from_env() -> Result<Self, TradingGateError> {
        Self::parse(std::env::var("TRADING_ENABLED").ok().as_deref())
    }

    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// `TRADING_ENABLED` was set to a value that is neither `"true"` nor `"false"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradingGateError;

impl std::fmt::Display for TradingGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TRADING_ENABLED must be exactly \"true\" or \"false\"")
    }
}

impl std::error::Error for TradingGateError {}

/// The capabilities a deployment can actually serve.
///
/// A capability is advertised only when its backing seam is wired. Trading
/// enabled does not imply a capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct WiredCapabilities {
    pub market: bool,
    pub quotes: bool,
    pub preview: bool,
    pub portfolio: bool,
    pub realtime: bool,
    pub wallet_limits: bool,
    pub execute: bool,
    pub limits: bool,
    pub twap: bool,
    pub rfq: bool,
    pub withdraw: bool,
    pub intelligence: bool,
}

impl WiredCapabilities {
    /// A backend that serves reads, previews and portfolio but cannot execute.
    pub fn read_only() -> Self {
        Self {
            market: true,
            quotes: true,
            preview: true,
            portfolio: true,
            ..Self::default()
        }
    }
}

/// A bootstrap document derived from the parsed gate and what is wired.
///
/// The kill switch is engaged unless trading is enabled *and* at least one
/// mutating capability is actually backed by a wired seam.
pub fn document_for(gate: TradingGate, wired: WiredCapabilities) -> BootstrapDocument {
    let mut document = BootstrapDocument::fail_closed();
    let capabilities = CapabilitySet {
        market: wired.market,
        realtime: wired.realtime,
        quotes: wired.quotes,
        preview: wired.preview,
        execute: wired.execute,
        limits: wired.limits,
        portfolio: wired.portfolio,
        intelligence: wired.intelligence,
        twitter: false,
        gmgn: false,
        okx: false,
        twap: wired.twap,
        rfq: wired.rfq,
        withdraw: wired.withdraw,
        wallet_limits: wired.wallet_limits,
    };
    let mutations_wired = wired.execute
        || wired.limits
        || wired.wallet_limits
        || wired.twap
        || wired.rfq
        || wired.withdraw;
    let trading_enabled = gate.is_enabled() && mutations_wired;
    document.capabilities = capabilities;
    document.trading_enabled = trading_enabled;
    document.kill_switch_enabled = !trading_enabled;
    document.kill_switch_reason = if gate.is_enabled() && !mutations_wired {
        Some("Trading is enabled but no mutating backend is wired.".to_string())
    } else if !gate.is_enabled() {
        Some("Trading is disabled by configuration.".to_string())
    } else {
        None
    };
    document
}

/// A bootstrap provider that always returns the same derived document.
#[derive(Debug)]
pub struct FixedBootstrap {
    document: BootstrapDocument,
}

impl FixedBootstrap {
    pub fn new(document: BootstrapDocument) -> Self {
        Self { document }
    }
}

impl BootstrapProvider for FixedBootstrap {
    fn document(&self) -> BootstrapDocument {
        self.document.clone()
    }
}

/// The resolved production opaque composition.
pub struct OpaqueProduction {
    pub state: OpaqueServiceState,
    pub gate: TradingGate,
}

impl std::fmt::Debug for OpaqueProduction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueProduction")
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// Everything the opaque composition needs, so the builder takes one argument.
pub struct OpaqueComposition {
    pub sessions: Arc<std::sync::Mutex<session_transport::SessionRegistry>>,
    pub clock: Arc<dyn OpaqueClock>,
    pub session_ttl_ms: i64,
    pub gate: TradingGate,
    /// Operator-injected command backend. `None` => fail-closed dispatcher.
    pub dispatcher: Option<Arc<dyn CommandDispatcher>>,
    pub wired: WiredCapabilities,
    /// Operator-injected realtime source. `None` => fail-closed source.
    pub stream_source: Option<Arc<dyn StreamSource>>,
    pub chains: Vec<ChainEntry>,
}

impl std::fmt::Debug for OpaqueComposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueComposition")
            .field("session_ttl_ms", &self.session_ttl_ms)
            .field("gate", &self.gate)
            .field("dispatcher_wired", &self.dispatcher.is_some())
            .field("stream_wired", &self.stream_source.is_some())
            .field("chains", &self.chains.len())
            .finish()
    }
}

/// Build the opaque state from the operator's composition.
///
/// With the fail-closed defaults (no dispatcher, nothing wired) the surface
/// denies every mutation and emits a single authenticated error frame — never
/// fabricated data.
pub fn build_opaque(composition: OpaqueComposition) -> Result<OpaqueProduction, &'static str> {
    let mut document = document_for(composition.gate, composition.wired);
    document.chains = composition.chains;
    let state = OpaqueServiceState::with_stream(
        composition.sessions,
        composition
            .dispatcher
            .unwrap_or_else(|| Arc::new(FailClosedDispatcher)),
        Arc::new(FixedBootstrap::new(document)),
        composition.clock,
        composition.session_ttl_ms,
        composition
            .stream_source
            .unwrap_or_else(|| Arc::new(FailClosedStreamSource)),
    )?;
    Ok(OpaqueProduction {
        state,
        gate: composition.gate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trading_gate_parses_strictly() {
        assert_eq!(TradingGate::parse(None).unwrap(), TradingGate::Disabled);
        assert_eq!(
            TradingGate::parse(Some("false")).unwrap(),
            TradingGate::Disabled
        );
        assert_eq!(
            TradingGate::parse(Some("true")).unwrap(),
            TradingGate::Enabled
        );
        // A typo must never enable execution.
        for bad in ["TRUE", "True", "1", "yes", " true", "true "] {
            assert_eq!(
                TradingGate::parse(Some(bad)),
                Err(TradingGateError),
                "{bad}"
            );
        }
    }

    #[test]
    fn enabling_trading_does_not_advertise_an_unwired_capability() {
        // Trading enabled but nothing wired: the document must stay fail-closed
        // and advertise no capability, because the deployment cannot serve it.
        let document = document_for(TradingGate::Enabled, WiredCapabilities::default());
        assert!(!document.trading_enabled);
        assert!(document.kill_switch_enabled);
        assert!(!document.capabilities.execute);
        assert!(!document.capabilities.preview);

        // A wired read-only backend advertises only its reads; execution stays
        // disabled and the kill switch stays engaged.
        let read_only = document_for(TradingGate::Enabled, WiredCapabilities::read_only());
        assert!(read_only.capabilities.preview);
        assert!(!read_only.capabilities.execute);
        assert!(!read_only.trading_enabled);
        assert!(read_only.kill_switch_enabled);

        // Execution is advertised and the kill switch disengages only when the
        // executing seam is actually wired and trading is enabled.
        let mut wired = WiredCapabilities::read_only();
        wired.execute = true;
        let live = document_for(TradingGate::Enabled, wired);
        assert!(live.capabilities.execute);
        assert!(live.trading_enabled);
        assert!(!live.kill_switch_enabled);

        // TRADING_ENABLED=false keeps the kill switch engaged even when wired.
        let disabled = document_for(TradingGate::Disabled, wired);
        assert!(!disabled.trading_enabled);
        assert!(disabled.kill_switch_enabled);
    }

    #[test]
    fn build_opaque_defaults_to_the_fail_closed_surface() {
        let sessions = Arc::new(std::sync::Mutex::new(
            session_transport::SessionRegistry::new(),
        ));
        let produced = build_opaque(OpaqueComposition {
            sessions,
            clock: Arc::new(crate::OpaqueSystemClock),
            session_ttl_ms: 60_000,
            gate: TradingGate::Enabled,
            dispatcher: None,
            wired: WiredCapabilities::default(),
            stream_source: None,
            chains: Vec::new(),
        })
        .expect("compose");
        // Even with TRADING_ENABLED=true, no wired backend means no capability.
        let document = produced.state.bootstrap().document();
        assert!(!document.trading_enabled);
        assert!(document.kill_switch_enabled);
    }
}
