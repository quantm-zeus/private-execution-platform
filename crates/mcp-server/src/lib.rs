//! # MCP server core (Phase 6 S2)
//!
//! Exposes the P53 [`agent_commands`] surface as a Model Context Protocol (MCP)
//! server over JSON-RPC 2.0. This crate is the **pure, testable dispatcher**
//! (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`) with
//! an injected [`AgentBackend`] port and a fail-closed production default
//! ([`UnavailableBackend`]).
//!
//! ## Boundaries
//! - The dispatcher performs no I/O, holds no signing/transfer/relay
//!   dependency, and never derives a valuation from the request. A trusted
//!   valuation is supplied by the backend; absent one, mutating commands fail
//!   closed in [`agent_commands::authorize`].
//! - Only authorized commands reach [`AgentBackend::execute`]. A denied,
//!   ambiguous, forbidden, or malformed command never reaches the backend.
//! - Every emitted text is static/redacted: no request addresses, amounts,
//!   queries, or order identifiers can appear in a response or error frame.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.
//!
//! The stdio/HTTP listener, real backend wiring, and Telegram transport are
//! later slices.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod schema;
mod server;

pub use backend::{AgentBackend, BackendOutcome, UnavailableBackend};
pub use error::McpError;
pub use server::McpServer;
