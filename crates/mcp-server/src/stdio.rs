//! # MCP stdio listener (Phase 6 S3)
//!
//! Thin, bounded newline-delimited JSON-RPC transport around the pure
//! [`McpServer`] dispatcher. One input line is one JSON-RPC frame; each frame is
//! dispatched at most once and produces at most one response line. The
//! reader/writer are injected so the loop is testable with in-memory buffers and
//! production can wire `tokio::io::stdin`/`stdout`.
//!
//! ## Boundaries
//! - No signing, transfer, network, or relay work: the loop only frames bytes
//!   and forwards complete frames to the dispatcher.
//! - A frame longer than [`StdioLimits::max_frame_bytes`] or not valid UTF-8 is
//!   rejected with a redacted error (`id: null`) and is never dispatched; the
//!   loop continues.
//! - The loop terminates on EOF or after [`StdioLimits::max_frames`] frames
//!   (`0` means unlimited).

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::backend::AgentBackend;
use crate::error::McpError;
use crate::server::McpServer;

/// Bounds applied by [`StdioServer::run`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StdioLimits {
    /// Maximum accepted frame length in bytes, excluding the line terminator.
    pub max_frame_bytes: usize,
    /// Maximum number of frames consumed before the loop stops; `0` is unlimited.
    pub max_frames: u64,
}

/// Bounded newline-delimited JSON-RPC stdio loop over a dispatcher.
pub struct StdioServer<B: AgentBackend> {
    server: McpServer<B>,
    limits: StdioLimits,
}

impl<B: AgentBackend> StdioServer<B> {
    /// Wraps `server` in a stdio transport with `limits`.
    pub fn new(server: McpServer<B>, limits: StdioLimits) -> Self {
        Self { server, limits }
    }

    /// Runs until EOF or the frame bound, returning the number of frames consumed.
    ///
    /// One non-blank input line is one frame. A dispatched request produces at
    /// most one LF-terminated response line, flushed before the next frame is
    /// read; a notification produces none. An oversized or non-UTF8 frame
    /// produces exactly one redacted error line with `id: null` and is not
    /// dispatched. Blank lines are skipped and do not count toward the bound.
    pub async fn run<R, W>(&self, mut reader: R, mut writer: W) -> Result<u64, McpError>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut processed: u64 = 0;
        loop {
            if self.limits.max_frames != 0 && processed >= self.limits.max_frames {
                return Ok(processed);
            }
            match read_frame(&mut reader, self.limits.max_frame_bytes).await {
                Ok(Frame::Eof) => return Ok(processed),
                Ok(Frame::Oversized) => {
                    processed += 1;
                    write_line(&mut writer, &error_frame(-32600, "frame too large")).await?;
                }
                Ok(Frame::Complete(bytes)) => {
                    if is_blank(&bytes) {
                        continue;
                    }
                    processed += 1;
                    match std::str::from_utf8(&bytes) {
                        Ok(frame) => {
                            let response = self.server.handle(frame).await;
                            if !response.is_empty() {
                                write_line(&mut writer, &response).await?;
                            }
                        }
                        Err(_) => {
                            write_line(&mut writer, &error_frame(-32700, "malformed request"))
                                .await?;
                        }
                    }
                }
                Err(_) => return Err(McpError::Transport),
            }
        }
    }
}

/// One consumed input line, bounded so an unbounded line cannot exhaust memory.
enum Frame {
    /// The reader reached EOF with no pending bytes.
    Eof,
    /// A complete line (possibly empty when blank), without the trailing `\n`.
    Complete(Vec<u8>),
    /// A line that exceeded the byte bound; its remainder was drained.
    Oversized,
}

/// Reads the next line, enforcing `max_frame_bytes` without unbounded buffering.
async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> std::io::Result<Frame> {
    // Accumulate one byte beyond the bound so a trailing `\r` of a CRLF
    // terminator does not count against the frame size; [`finish_line`] drops
    // it and re-checks the bound. Without this, a CRLF frame whose content is
    // exactly `max_frame_bytes` would be misclassified as oversized.
    let raw_limit = max_frame_bytes.saturating_add(1);
    let mut line: Vec<u8> = Vec::new();
    let mut saw_bytes = false;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if !saw_bytes {
                return Ok(Frame::Eof);
            }
            return Ok(if oversized {
                Frame::Oversized
            } else {
                finish_line(line, max_frame_bytes)
            });
        }
        saw_bytes = true;
        let newline = available.iter().position(|&byte| byte == b'\n');
        let content_len = newline.unwrap_or(available.len());
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if oversized {
            reader.consume(consumed);
            if newline.is_some() {
                return Ok(Frame::Oversized);
            }
            continue;
        }
        if line.len().saturating_add(content_len) > raw_limit {
            oversized = true;
            reader.consume(consumed);
            if newline.is_some() {
                return Ok(Frame::Oversized);
            }
            continue;
        }
        line.extend_from_slice(&available[..content_len]);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(finish_line(line, max_frame_bytes));
        }
    }
}

/// Drops a CRLF terminator's `\r` and applies the exact frame bound.
fn finish_line(mut line: Vec<u8>, max_frame_bytes: usize) -> Frame {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > max_frame_bytes {
        Frame::Oversized
    } else {
        Frame::Complete(line)
    }
}

/// True when a frame carries no JSON-RPC content (empty or ASCII whitespace).
fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_whitespace)
}

/// Serializes a redacted JSON-RPC error with a null id.
fn error_frame(code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

/// Writes one response line and flushes it before the next frame is read.
async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> Result<(), McpError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|_| McpError::Transport)?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|_| McpError::Transport)?;
    writer.flush().await.map_err(|_| McpError::Transport)
}
