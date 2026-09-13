//! # Paid social intelligence (Phase 7)
//!
//! A semantically-typed `SocialIntelService` that spends a bounded paid-provider
//! budget only where the PRD permits: **active-position risk**, **high-conviction
//! pre-trade**, and — if budget permits — a **promising candidate**. Broad
//! discovery is impossible by construction: there is no discovery priority and
//! the two pre-trade priorities require an eligible candidate.
//!
//! ## Boundaries
//! - **Provider failure degrades intelligence only.** A failed fetch is
//!   negatively cached and, when one exists, a stale fallback is served. The
//!   service has no execution dependency at all, so budget exhaustion or a
//!   provider outage can never disable execution (INVARIANT #6).
//! - **Bounded output.** Snapshots carry a closed [`SocialSignalKind`] vocabulary
//!   and a bounded weight, never raw upstream text, influencer handles, token
//!   amounts, or credentials.
//! - **One cache/budget.** Reuses `provider-broker`'s [`provider_broker::ProviderBudget`],
//!   [`provider_broker::LogicalCache`], and [`provider_broker::DegradedReason`] so
//!   the paid-social path obeys the same budget/cache semantics as the other
//!   intelligence providers.
//! - **No live transport.** The only provider port is injected; the production
//!   default ([`UnavailableSocialProvider`]) fails closed.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod error;
mod policy;
mod provider;
mod service;

pub use error::SocialProviderError;
pub use policy::{SocialPolicy, SocialPriority};
pub use provider::{
    SocialProvider, SocialRequest, SocialSignal, SocialSignalKind, SocialSnapshot,
    UnavailableSocialProvider, MAX_SIGNALS, MAX_WEIGHT_BPS,
};
pub use service::{SocialIntelService, SocialMeta, SocialResponse};
