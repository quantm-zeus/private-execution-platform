//! Encrypted realtime stream service (BR-2 / BR-15).
//!
//! The browser opens `GET /v1/stream` (same-origin WebSocket, binary frames
//! only). The edge relays ciphertext to this service over the internal mTLS
//! bidi stream. Because the WebSocket carries no browser -> server frame by
//! itself, the browser first sends one *encrypted* `subscribe` envelope whose
//! cleartext `kid` identifies the session (BR-5) and whose AEAD plaintext
//! carries the client's applied-sequence high-water mark.
//!
//! This module owns the only place plaintext frames exist: it selects the
//! injected [`StreamSource`], stamps the authenticated `server_time_ms`
//! (BR-15), and seals each frame under the session's monotonic stream sequence.
//! With no configured source the stream stays fail-closed: the client receives
//! one authenticated `error` frame and no state, so it never renders fabricated
//! data and never opens the capital-committing circuit breaker.
//!
//! Sequence epochs: [`session_transport::ServerSession`] never resets its stream
//! sequence for a `kid`. A backend restart that must reset its sequence space
//! requires a fresh BR-5 handoff (new `kid`), exactly as the web client assumes.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rpc_contracts::relay_stream_service::RelayStreamService;
use rpc_contracts::{validate_stream_frame, StreamFrame as WireStreamFrame};
use serde_json::{json, Value};
use session_transport::{
    parse_wire_envelope, Purpose, SessionRegistry, StreamControlRequest, StreamFrame, StreamOp,
};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::opaque::{OpaqueClock, OpaqueServiceState};

/// Outbound frame-count cap per stream connection (a secondary bound; the byte
/// budget below is the primary one).
const OUTBOUND_CAPACITY: usize = 64;
/// Maximum sealed bytes buffered for one connection before the driver stops and
/// lets the client resync. Bounds memory even if a subscriber stops reading.
const OUTBOUND_BYTES_BUDGET: usize = 4 * 1024 * 1024;
/// Frames the fail-closed source emits before ending the stream.
const FAIL_CLOSED_FRAMES: usize = 1;

/// A frame the injected source wants delivered. The driver stamps
/// `server_time_ms` from its own clock; the source never supplies the
/// authenticated clock.
#[derive(Debug, Clone)]
pub struct SourceFrame {
    pub op: StreamOp,
    pub channel: String,
    pub priority: Option<u8>,
    pub entity_key: Option<String>,
    pub slot: Option<u64>,
    pub source_age_ms: u64,
    pub payload: Option<Value>,
}

impl SourceFrame {
    pub fn snapshot(channel: impl Into<String>, payload: Value, slot: Option<u64>) -> Self {
        Self {
            op: StreamOp::Snapshot,
            channel: channel.into(),
            priority: None,
            entity_key: None,
            slot,
            source_age_ms: 0,
            payload: Some(payload),
        }
    }

    pub fn delta(
        channel: impl Into<String>,
        entity_key: impl Into<String>,
        payload: Value,
        slot: Option<u64>,
    ) -> Self {
        Self {
            op: StreamOp::Delta,
            channel: channel.into(),
            priority: None,
            entity_key: Some(entity_key.into()),
            slot,
            source_age_ms: 0,
            payload: Some(payload),
        }
    }

    pub fn heartbeat(channel: impl Into<String>) -> Self {
        Self {
            op: StreamOp::Heartbeat,
            channel: channel.into(),
            priority: None,
            entity_key: None,
            slot: None,
            source_age_ms: 0,
            payload: None,
        }
    }

    pub fn error(channel: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            op: StreamOp::Error,
            channel: channel.into(),
            priority: Some(0),
            entity_key: None,
            slot: None,
            source_age_ms: 0,
            payload: Some(json!({ "code": "unavailable", "message": message.into() })),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_entity_key(mut self, entity_key: impl Into<String>) -> Self {
        self.entity_key = Some(entity_key.into());
        self
    }

    pub fn with_source_age_ms(mut self, source_age_ms: u64) -> Self {
        self.source_age_ms = source_age_ms;
        self
    }

    /// Convert to the wire frame, stamping the authenticated server clock.
    pub fn into_stream_frame(self, server_time_ms: i64) -> StreamFrame {
        StreamFrame {
            op: self.op,
            channel: self.channel,
            priority: self.priority,
            entity_key: self.entity_key,
            slot: self.slot,
            source_age_ms: self.source_age_ms,
            server_time_ms,
            payload: self.payload,
        }
    }
}

/// Injected authoritative realtime data source.
///
/// Implementations own market/order state; the stream service only frames and
/// encrypts. `snapshot` MUST return the full authoritative state at or after
/// `from_seq` (the client's high-water mark) so a recovery snapshot can never
/// roll the client backward.
#[async_trait]
pub trait StreamSource: Send + Sync {
    /// Full authoritative state, or `None` when the source cannot produce one.
    async fn snapshot(&self, from_seq: Option<u64>) -> Option<SourceFrame>;
    /// Next ordered delta; `None` ends the stream.
    async fn next_delta(&self) -> Option<SourceFrame>;
    /// Frames emitted when no snapshot is available. Defaults to one
    /// authenticated error frame (fail-closed: no fabricated state).
    async fn unavailable(&self) -> Vec<SourceFrame> {
        vec![SourceFrame::error(
            "system",
            "Realtime data source is not configured.",
        )]
    }
}

/// Production fail-closed source: no state, no deltas.
#[derive(Debug, Default)]
pub struct FailClosedStreamSource;

#[async_trait]
impl StreamSource for FailClosedStreamSource {
    async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
        None
    }

    async fn next_delta(&self) -> Option<SourceFrame> {
        None
    }
}

/// Async sink used to hand sealed frames to the transport (gRPC) or a test.
#[async_trait]
pub trait FrameSink: Send {
    /// Returns `false` when the transport is gone and the driver must stop.
    async fn send(&mut self, bytes: Vec<u8>) -> bool;
}

/// Sink that forwards frames into the gRPC outbound channel under a byte budget.
struct ChannelSink {
    sender: mpsc::Sender<Result<WireStreamFrame, Status>>,
    /// Sealed bytes currently buffered for this connection (released by the
    /// outbound stream as frames are consumed).
    pending: Arc<AtomicUsize>,
}

impl ChannelSink {
    fn new(
        sender: mpsc::Sender<Result<WireStreamFrame, Status>>,
        pending: Arc<AtomicUsize>,
    ) -> Self {
        Self { sender, pending }
    }

    /// Terminate the outbound stream with an opaque status.
    async fn fail(&mut self, status: Status) -> bool {
        self.sender.send(Err(status)).await.is_ok()
    }
}

#[async_trait]
impl FrameSink for ChannelSink {
    async fn send(&mut self, bytes: Vec<u8>) -> bool {
        // Byte-budgeted backpressure: stop the driver rather than queue without
        // bound when the peer stops reading. A single oversized frame (bounded
        // upstream by the frame validation) also stops.
        let len = bytes.len();
        if len > OUTBOUND_BYTES_BUDGET
            || self.pending.load(Ordering::Acquire).saturating_add(len) > OUTBOUND_BYTES_BUDGET
        {
            return false;
        }
        self.pending.fetch_add(len, Ordering::AcqRel);
        let frame = WireStreamFrame { ciphertext: bytes };
        if self.sender.send(Ok(frame)).await.is_err() {
            self.pending.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        true
    }
}

/// Key-id type used to index the hub.
type Kid = [u8; session_transport::KID_BYTES];
/// Resync bookkeeping per session key.
type Slots = HashMap<Kid, Slot>;

/// Per-kid coordination between the HTTP `/v1/sync` probe and the active stream
/// connection.
#[derive(Default)]
pub struct StreamHub {
    inner: Mutex<Slots>,
}

struct Slot {
    generation: u64,
    resync: Option<u64>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for StreamHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.inner.lock().map(|map| map.len()).unwrap_or(0);
        f.debug_struct("StreamHub").field("sessions", &len).finish()
    }
}

impl StreamHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a (re)connect. Returns the connection generation and the
    /// notification handle; a stale generation can never consume a resync
    /// request meant for the current connection.
    pub fn register(&self, kid: Kid) -> (u64, Arc<Notify>) {
        let mut map = self.lock();
        let slot = map.entry(kid).or_insert_with(|| Slot {
            generation: 0,
            resync: None,
            notify: Arc::new(Notify::new()),
        });
        slot.generation = slot.generation.wrapping_add(1);
        slot.resync = None;
        (slot.generation, slot.notify.clone())
    }

    /// Ask the active connection for a fresh snapshot at/after `from_seq`.
    pub fn request_resync(&self, kid: Kid, from_seq: Option<u64>) {
        let mut map = self.lock();
        if let Some(slot) = map.get_mut(&kid) {
            slot.resync = Some(from_seq.unwrap_or(0));
            // `notify_one` (not `notify_waiters`) stores a permit when no waiter
            // is registered, so a resync that lands in the window between the
            // driver's `take_resync` check and its `notified()` await is not
            // lost (which would wedge recovery on an idle source).
            slot.notify.notify_one();
        }
    }

    /// Consume a pending resync for the current generation only.
    fn take_resync(&self, kid: Kid, generation: u64) -> Option<u64> {
        let mut map = self.lock();
        let slot = map.get_mut(&kid)?;
        if slot.generation != generation {
            return None;
        }
        slot.resync.take()
    }

    /// True while `generation` is the live connection for `kid`. A superseded
    /// connection must stop emitting: it would otherwise advance the shared
    /// monotonic stream sequence with frames the client never sees, forcing a
    /// spurious gap/resync.
    fn is_current(&self, kid: Kid, generation: u64) -> bool {
        let map = self.lock();
        map.get(&kid)
            .is_some_and(|slot| slot.generation == generation)
    }

    /// Drop the slot when its connection ends. Only the current generation may
    /// release, so a superseded connection cannot evict a newer one. This keeps
    /// the map bounded by live connections rather than by historical unlocks.
    fn release(&self, kid: Kid, generation: u64) {
        let mut map = self.lock();
        if map
            .get(&kid)
            .is_some_and(|slot| slot.generation == generation)
        {
            map.remove(&kid);
        }
    }

    /// Test/diagnostic accessor: number of live stream slots.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Drives one stream connection: initial snapshot, ordered deltas, and
/// resync-triggered fresh snapshots.
pub struct StreamDriver {
    sessions: Arc<Mutex<SessionRegistry>>,
    hub: Arc<StreamHub>,
    clock: Arc<dyn OpaqueClock>,
    source: Arc<dyn StreamSource>,
}

impl std::fmt::Debug for StreamDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDriver").finish_non_exhaustive()
    }
}

impl StreamDriver {
    pub fn new(
        sessions: Arc<Mutex<SessionRegistry>>,
        hub: Arc<StreamHub>,
        clock: Arc<dyn OpaqueClock>,
        source: Arc<dyn StreamSource>,
    ) -> Self {
        Self {
            sessions,
            hub,
            clock,
            source,
        }
    }

    /// Run until the source is exhausted / unavailable, the session is gone, or
    /// the sink rejects a frame.
    pub async fn run(
        &self,
        kid: Kid,
        from_seq: Option<u64>,
        generation: u64,
        notify: Arc<Notify>,
        sink: &mut dyn FrameSink,
    ) {
        if !self.emit_snapshot(kid, from_seq, generation, sink).await {
            return;
        }
        loop {
            if let Some(from) = self.hub.take_resync(kid, generation) {
                if !self.emit_snapshot(kid, Some(from), generation, sink).await {
                    return;
                }
                continue;
            }
            tokio::select! {
                _ = notify.notified() => continue,
                delta = self.source.next_delta() => match delta {
                    Some(frame) => {
                        if !self.emit(kid, frame, generation, sink).await {
                            return;
                        }
                    }
                    None => return,
                },
            }
        }
    }

    async fn emit_snapshot(
        &self,
        kid: Kid,
        from_seq: Option<u64>,
        generation: u64,
        sink: &mut dyn FrameSink,
    ) -> bool {
        match self.source.snapshot(from_seq).await {
            Some(frame) => self.emit(kid, frame, generation, sink).await,
            None => {
                // Fail closed: surface the unavailability to the client as an
                // authenticated frame, then end the stream; never fabricate state.
                for frame in self
                    .source
                    .unavailable()
                    .await
                    .into_iter()
                    .take(FAIL_CLOSED_FRAMES)
                {
                    if !self.emit(kid, frame, generation, sink).await {
                        return false;
                    }
                }
                false
            }
        }
    }

    async fn emit(
        &self,
        kid: Kid,
        frame: SourceFrame,
        generation: u64,
        sink: &mut dyn FrameSink,
    ) -> bool {
        // A superseded connection must not advance the shared stream sequence.
        if !self.hub.is_current(kid, generation) {
            return false;
        }
        let Some(now) = self.clock.now_ms() else {
            return false;
        };
        let sealed = {
            let mut sessions = match self.sessions.lock() {
                Ok(sessions) => sessions,
                Err(_) => return false,
            };
            match sessions.get_mut(&kid) {
                Some(session) => session.seal_stream_frame(&frame.into_stream_frame(now)),
                None => return false,
            }
        };
        match sealed {
            Ok(envelope) => sink.send(envelope.to_wire_bytes()).await,
            // A stale server clock or malformed source frame must stop the
            // stream rather than emit something a client could misread.
            Err(_) => false,
        }
    }
}

/// gRPC service bridging the edge's opaque bidi stream to the driver.
pub struct EncryptedStreamService {
    state: OpaqueServiceState,
}

impl EncryptedStreamService {
    pub fn new(state: OpaqueServiceState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl RelayStreamService for EncryptedStreamService {
    type StreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<WireStreamFrame, Status>> + Send>>;

    async fn stream(
        &self,
        request: Request<Streaming<WireStreamFrame>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        // Respond immediately with the outbound half. The browser cannot send
        // its encrypted `subscribe` frame until the edge has completed the
        // WebSocket upgrade, so the first inbound frame is read *after* the
        // response headers are returned (reading before would deadlock).
        let mut inbound = request.into_inner();
        let (sender, receiver) =
            mpsc::channel::<Result<WireStreamFrame, Status>>(OUTBOUND_CAPACITY);
        let pending = Arc::new(AtomicUsize::new(0));
        let state = self.state.clone();
        let sink_pending = pending.clone();
        tokio::spawn(async move {
            let mut sink = ChannelSink::new(sender, sink_pending);
            if let Err(status) = run_subscription(&state, &mut inbound, &mut sink).await {
                let _ = sink.fail(status).await;
            }
        });
        // Release the byte budget as the transport drains frames.
        let outbound = ReceiverStream::new(receiver).map(move |item| {
            if let Ok(frame) = &item {
                pending.fetch_sub(frame.ciphertext.len(), Ordering::AcqRel);
            }
            item
        });
        Ok(Response::new(Box::pin(outbound)))
    }
}

/// Authenticate the encrypted subscription and then drive frames until the
/// source/session/transport ends.
async fn run_subscription(
    state: &OpaqueServiceState,
    inbound: &mut Streaming<WireStreamFrame>,
    sink: &mut ChannelSink,
) -> Result<(), Status> {
    let first = inbound
        .message()
        .await
        .map_err(|_| Status::unavailable("stream unavailable"))?
        .ok_or_else(|| Status::invalid_argument("stream subscription required"))?;
    validate_stream_frame(&first).map_err(|_| Status::invalid_argument("invalid frame"))?;

    let now = state
        .clock()
        .now_ms()
        .ok_or_else(|| Status::unavailable("stream unavailable"))?;
    let envelope = parse_wire_envelope(&first.ciphertext)
        .map_err(|_| Status::invalid_argument("invalid frame"))?;
    let kid = envelope
        .decode_kid()
        .map_err(|_| Status::invalid_argument("invalid frame"))?;
    let plaintext = {
        let sessions_handle = state.sessions();
        let mut sessions = sessions_handle
            .lock()
            .map_err(|_| Status::unavailable("stream unavailable"))?;
        sessions.prune(now);
        let session = sessions
            .get_mut(&kid)
            .ok_or_else(|| Status::unauthenticated("session unavailable"))?;
        session
            .open(&envelope, now, Purpose::Stream)
            .map_err(|_| Status::unauthenticated("session unavailable"))?
    };
    let subscribe = StreamControlRequest::parse(&plaintext)
        .map_err(|_| Status::invalid_argument("invalid subscription"))?;

    let (generation, notify) = state.stream_hub().register(kid);
    let driver = state.stream_driver();
    driver
        .run(kid, subscribe.from_seq, generation, notify, sink)
        .await;
    // The connection ended: release the hub slot so repeated reconnects cannot
    // grow the map for the process lifetime. `release` is generation-guarded.
    state.stream_hub().release(kid, generation);
    Ok(())
}

/// Convenience import used by the router wiring (kept for symmetry with the
/// unary relay service).
pub type EncryptedStreamServiceServer =
    rpc_contracts::relay_stream_service::RelayStreamServiceServer<EncryptedStreamService>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use crypto_envelope::hpke::AppDirectionKeys;
    use session_transport::{ClientSession, ServerSession, SessionError as StreamSessionError};

    const KID: [u8; 16] = [0x7Cu8; 16];

    fn keys() -> AppDirectionKeys {
        AppDirectionKeys::from_bytes([0x31u8; 32], [0x42u8; 32])
    }

    struct FixedClock(i64);
    impl OpaqueClock for FixedClock {
        fn now_ms(&self) -> Option<i64> {
            Some(self.0)
        }
    }

    /// Clock that advances so successive frames carry distinct, non-decreasing
    /// server times.
    struct TickClock(AtomicUsize);
    impl OpaqueClock for TickClock {
        fn now_ms(&self) -> Option<i64> {
            let tick = self.0.fetch_add(1, Ordering::SeqCst) as i64;
            Some(1_000 + tick)
        }
    }

    /// Source that yields a snapshot then a bounded delta stream.
    struct ScriptedSource {
        snapshots: Mutex<Vec<SourceFrame>>,
        deltas: Mutex<Vec<SourceFrame>>,
    }

    #[async_trait]
    impl StreamSource for ScriptedSource {
        async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
            let mut snapshots = self.snapshots.lock().unwrap();
            if snapshots.is_empty() {
                None
            } else {
                Some(snapshots.remove(0))
            }
        }

        async fn next_delta(&self) -> Option<SourceFrame> {
            let mut deltas = self.deltas.lock().unwrap();
            if deltas.is_empty() {
                None
            } else {
                Some(deltas.remove(0))
            }
        }
    }

    /// Source that never has a snapshot (production fail-closed).
    struct NoSource;
    #[async_trait]
    impl StreamSource for NoSource {
        async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
            None
        }
        async fn next_delta(&self) -> Option<SourceFrame> {
            None
        }
    }

    struct VecSink(Vec<Vec<u8>>);
    #[async_trait]
    impl FrameSink for VecSink {
        async fn send(&mut self, bytes: Vec<u8>) -> bool {
            self.0.push(bytes);
            true
        }
    }

    struct RejectingSink;
    #[async_trait]
    impl FrameSink for RejectingSink {
        async fn send(&mut self, _bytes: Vec<u8>) -> bool {
            false
        }
    }

    fn registry(now: i64) -> Arc<Mutex<SessionRegistry>> {
        let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
        sessions
            .lock()
            .unwrap()
            .insert(ServerSession::new(KID, &keys(), now + 600_000).unwrap())
            .unwrap();
        sessions
    }

    fn driver_with(
        source: Arc<dyn StreamSource>,
        sessions: Arc<Mutex<SessionRegistry>>,
        hub: Arc<StreamHub>,
        clock: Arc<dyn OpaqueClock>,
    ) -> StreamDriver {
        StreamDriver::new(sessions, hub, clock, source)
    }

    #[tokio::test]
    async fn emits_snapshot_then_contiguous_deltas_with_monotonic_server_time() {
        let source = Arc::new(ScriptedSource {
            snapshots: Mutex::new(vec![SourceFrame::snapshot(
                "market",
                json!({ "pools": [] }),
                Some(10),
            )]),
            deltas: Mutex::new(vec![
                SourceFrame::delta("market", "market:eth", json!({ "price": 1 }), Some(11)),
                SourceFrame::heartbeat("system"),
            ]),
        });
        let sessions = registry(0);
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = driver_with(
            source,
            sessions,
            hub,
            Arc::new(TickClock(AtomicUsize::new(0))),
        );

        let mut sink = VecSink(Vec::new());
        driver.run(KID, None, generation, notify, &mut sink).await;
        assert_eq!(sink.0.len(), 3);

        let mut client = ClientSession::new(KID, &keys()).unwrap();
        let mut seqs = Vec::new();
        let mut times = Vec::new();
        for bytes in &sink.0 {
            let envelope = parse_wire_envelope(bytes).unwrap();
            seqs.push(envelope.sequence);
            let plaintext = client.open(&envelope).unwrap();
            let frame: StreamFrame = serde_json::from_slice(&plaintext).unwrap();
            times.push(frame.server_time_ms);
        }
        assert_eq!(seqs, vec![0, 1, 2]);
        assert!(times.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[tokio::test]
    async fn resync_request_forces_a_fresh_snapshot() {
        let source = Arc::new(ScriptedSource {
            snapshots: Mutex::new(vec![
                SourceFrame::snapshot("market", json!({ "v": 1 }), None),
                SourceFrame::snapshot("market", json!({ "v": 2 }), None),
            ]),
            deltas: Mutex::new(Vec::new()),
        });
        let sessions = registry(0);
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = driver_with(
            source,
            sessions.clone(),
            hub.clone(),
            Arc::new(TickClock(AtomicUsize::new(0))),
        );

        // Request a resync before running: the driver emits the snapshot, then
        // observes the pending request and emits a second, newer snapshot.
        hub.request_resync(KID, Some(0));
        let mut sink = VecSink(Vec::new());
        driver.run(KID, None, generation, notify, &mut sink).await;
        assert_eq!(sink.0.len(), 2);

        let mut client = ClientSession::new(KID, &keys()).unwrap();
        let first = parse_wire_envelope(&sink.0[0]).unwrap();
        let second = parse_wire_envelope(&sink.0[1]).unwrap();
        assert!(second.sequence > first.sequence);
        let body: Value = serde_json::from_slice(&client.open(&second).unwrap()).unwrap();
        assert_eq!(body["payload"]["v"], 2);
    }

    #[tokio::test]
    async fn stale_generation_cannot_consume_a_resync() {
        let hub = StreamHub::new();
        let (generation, _notify) = hub.register(KID);
        let (newer, _newer_notify) = hub.register(KID);
        assert_ne!(generation, newer);
        hub.request_resync(KID, Some(5));
        assert_eq!(hub.take_resync(KID, generation), None);
        assert_eq!(hub.take_resync(KID, newer), Some(5));
    }

    #[tokio::test]
    async fn fail_closed_source_emits_one_authenticated_error_and_stops() {
        let sessions = registry(0);
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = driver_with(
            Arc::new(NoSource),
            sessions,
            hub,
            Arc::new(FixedClock(5_000)),
        );
        let mut sink = VecSink(Vec::new());
        driver.run(KID, None, generation, notify, &mut sink).await;
        assert_eq!(sink.0.len(), 1);

        let mut client = ClientSession::new(KID, &keys()).unwrap();
        let envelope = parse_wire_envelope(&sink.0[0]).unwrap();
        let frame: StreamFrame = serde_json::from_slice(&client.open(&envelope).unwrap()).unwrap();
        assert_eq!(frame.op, StreamOp::Error);
        assert_eq!(frame.server_time_ms, 5_000);
        assert!(matches!(
            client.open(&envelope),
            Err(StreamSessionError::ReplayDetected)
        ));
    }

    #[tokio::test]
    async fn a_closed_sink_stops_immediately() {
        let source = Arc::new(ScriptedSource {
            snapshots: Mutex::new(vec![SourceFrame::snapshot("market", json!({}), None)]),
            deltas: Mutex::new(Vec::new()),
        });
        let sessions = registry(0);
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = driver_with(source, sessions, hub, Arc::new(FixedClock(1_000)));
        let mut sink = RejectingSink;
        // Returns without panicking and without emitting anything further.
        driver.run(KID, None, generation, notify, &mut sink).await;
    }

    #[tokio::test]
    async fn driver_stops_when_the_session_is_unknown() {
        let source = Arc::new(ScriptedSource {
            snapshots: Mutex::new(vec![SourceFrame::snapshot("market", json!({}), None)]),
            deltas: Mutex::new(Vec::new()),
        });
        let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = driver_with(source, sessions, hub, Arc::new(FixedClock(1_000)));
        let mut sink = VecSink(Vec::new());
        driver.run(KID, None, generation, notify, &mut sink).await;
        assert!(sink.0.is_empty());
    }

    #[tokio::test]
    async fn grpc_stream_subscribe_authenticates_and_emits_the_snapshot() {
        use crate::opaque::{FailClosedBootstrap, FailClosedDispatcher};
        use rpc_contracts::relay_stream_service_client::RelayStreamServiceClient;
        use rpc_contracts::relay_stream_service_server::RelayStreamServiceServer;
        use tokio_stream::wrappers::{ReceiverStream as Deferred, TcpListenerStream};

        let sessions = registry(0);
        let source = Arc::new(ScriptedSource {
            snapshots: Mutex::new(vec![SourceFrame::snapshot(
                "market",
                json!({ "pools": [] }),
                Some(3),
            )]),
            deltas: Mutex::new(Vec::new()),
        });
        let state = OpaqueServiceState::with_stream(
            sessions,
            Arc::new(FailClosedDispatcher),
            Arc::new(FailClosedBootstrap),
            Arc::new(TickClock(AtomicUsize::new(0))),
            600_000,
            source,
        )
        .unwrap();
        let service = EncryptedStreamService::new(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(RelayStreamServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await;
        });

        let mut client = {
            let mut attempt = 0;
            loop {
                match RelayStreamServiceClient::connect(format!("http://{address}")).await {
                    Ok(client) => break client,
                    Err(error) if attempt < 50 => {
                        attempt += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        let _ = error;
                    }
                    Err(error) => panic!("client connect: {error}"),
                }
            }
        };

        let (sender, receiver) = mpsc::channel(8);
        let mut session_client = ClientSession::new(KID, &keys()).unwrap();
        let subscribe = session_client
            .seal_next(br#"{"op":"subscribe","from_seq":null,"request_id":"sub"}"#)
            .unwrap();
        sender
            .send(WireStreamFrame {
                ciphertext: subscribe.to_wire_bytes(),
            })
            .await
            .unwrap();

        let response = client
            .stream(Request::new(Deferred::new(receiver)))
            .await
            .expect("stream opens before the subscribe is read");
        let mut outbound = response.into_inner();
        let frame = outbound
            .message()
            .await
            .expect("frame")
            .expect("sealed frame");
        let envelope = parse_wire_envelope(&frame.ciphertext).unwrap();
        assert_eq!(envelope.sequence, 0);
        let inner: StreamFrame =
            serde_json::from_slice(&session_client.open(&envelope).unwrap()).unwrap();
        assert_eq!(inner.op, StreamOp::Snapshot);
        assert_eq!(inner.payload.unwrap()["pools"], json!([]));
    }

    /// Source whose delta stream never resolves, so the driver blocks in
    /// `select!` and only the resync notification can wake it.
    struct IdleSource {
        snapshots: Mutex<Vec<SourceFrame>>,
    }

    #[async_trait]
    impl StreamSource for IdleSource {
        async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
            let mut snapshots = self.snapshots.lock().unwrap();
            if snapshots.is_empty() {
                None
            } else {
                Some(snapshots.remove(0))
            }
        }

        async fn next_delta(&self) -> Option<SourceFrame> {
            std::future::pending::<()>().await;
            None
        }
    }

    struct ArcSink(Arc<Mutex<Vec<Vec<u8>>>>);

    #[async_trait]
    impl FrameSink for ArcSink {
        async fn send(&mut self, bytes: Vec<u8>) -> bool {
            self.0.lock().unwrap().push(bytes);
            true
        }
    }

    /// Regression: a `/v1/sync` arriving while the driver is between its
    /// `take_resync` check and `notified()` must not be lost.
    #[tokio::test]
    async fn resync_wakes_an_idle_driver() {
        let source = Arc::new(IdleSource {
            snapshots: Mutex::new(vec![
                SourceFrame::snapshot("market", json!({ "v": 1 }), None),
                SourceFrame::snapshot("market", json!({ "v": 2 }), None),
            ]),
        });
        let sessions = registry(0);
        let hub = Arc::new(StreamHub::new());
        let (generation, notify) = hub.register(KID);
        let driver = StreamDriver::new(
            sessions,
            hub.clone(),
            Arc::new(TickClock(AtomicUsize::new(0))),
            source,
        );
        let frames = Arc::new(Mutex::new(Vec::new()));
        let frames_clone = frames.clone();
        let handle = tokio::spawn(async move {
            let mut sink = ArcSink(frames_clone);
            driver.run(KID, None, generation, notify, &mut sink).await;
        });

        for _ in 0..200 {
            if frames.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(frames.lock().unwrap().len(), 1, "initial snapshot");
        hub.request_resync(KID, Some(0));
        for _ in 0..200 {
            if frames.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            frames.lock().unwrap().len(),
            2,
            "resync must wake an idle driver"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn hub_release_removes_the_slot_and_is_generation_guarded() {
        let hub = StreamHub::new();
        let (first, _notify) = hub.register(KID);
        assert_eq!(hub.len(), 1);
        let (second, _notify) = hub.register(KID);
        // A superseded connection cannot evict the newer slot.
        hub.release(KID, first);
        assert_eq!(hub.len(), 1);
        hub.release(KID, second);
        assert_eq!(hub.len(), 0);
    }
}
