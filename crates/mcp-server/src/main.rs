//! Fail-closed MCP stdio server binary (Phase 6 S3).
//!
//! Wires `tokio` stdin/stdout to the P55 dispatcher behind the bounded stdio
//! listener. The backend is the fail-closed [`UnavailableBackend`] and trading
//! is unconditionally disabled (no environment parsing that could enable it);
//! every command is a redacted read result or a static denial.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::process::ExitCode;

use agent_commands::AgentCapabilities;
use mcp_server::{McpServer, StdioLimits, StdioServer, UnavailableBackend};
use tokio::io::BufReader;

/// Fixed frame bound: 1 MiB per frame, unlimited frame count.
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_FRAMES: u64 = 0;

#[tokio::main]
async fn main() -> ExitCode {
    // Fail-closed capabilities: trading disabled, no chain allowed, zero
    // notional. Built from a constant, never from the request or the env.
    let capabilities = AgentCapabilities::new(false, HashSet::new(), 0);
    let server = McpServer::new(UnavailableBackend, capabilities);
    let stdio = StdioServer::new(
        server,
        StdioLimits {
            max_frame_bytes: MAX_FRAME_BYTES,
            max_frames: MAX_FRAMES,
        },
    );

    let reader = BufReader::new(tokio::io::stdin());
    let writer = tokio::io::stdout();
    match stdio.run(reader, writer).await {
        Ok(_processed) => ExitCode::SUCCESS,
        Err(_transport) => ExitCode::FAILURE,
    }
}
