//! Private web command contract layer (BR-9 / BR-10 / BR-12 / BR-14).
//!
//! The canonical `agent-commands` vocabulary is shared by MCP and Telegram and
//! owns the actual Trading Core operations. The private web surface additionally
//! needs operations and response guarantees those channels do not:
//!
//! * BR-9: authoritative reconciliation reads (`get_order`, `get_order` by
//!   client reference, withdrawal-by-request, correlated execution progress) so
//!   the UI can resolve an UNKNOWN write instead of self-attesting.
//! * BR-10: an execute success MUST carry a matching `router_source` echo and a
//!   stable `execution_id`; a missing/mismatched echo is indeterminate, never a
//!   false success.
//! * BR-12: a `place_limit_order` 2xx MUST carry a non-empty `order_id`.
//! * BR-14: trading-wallet limit read/write.
//!
//! The layer delegates canonical operations unchanged and applies the web-only
//! reconciliation/normalisation above. It derives **nothing**: a value the
//! backend did not return is an indeterminate denial, not a fabricated success.

use std::sync::Arc;

use agent_commands::AgentCapabilities;
use async_trait::async_trait;
use serde_json::Value;
use session_transport::{CommandDenial, CommandRequest, DenialCode};

use crate::opaque::CommandDispatcher;

/// Authoritative source for the web-only operations.
///
/// Implementations own the durable order store, wallet-limit policy and
/// reconciliation reads. The default [`FailClosedWebContract`] serves nothing,
/// so the UI renders `capability_missing` and never fabricates a resolution.
#[async_trait]
pub trait WebContractBackend: Send + Sync {
    /// BR-14 authoritative trading-wallet limits document.
    async fn wallet_limits(&self) -> Result<Value, CommandDenial>;
    /// BR-14 idempotent limit write. The backend is the authorization boundary.
    async fn set_wallet_limits(
        &self,
        limits: &Value,
        idempotency_key: &str,
    ) -> Result<Value, CommandDenial>;
    /// BR-9 resolve a known limit order by its backend id.
    async fn order_by_id(&self, order_id: &str) -> Result<Value, CommandDenial>;
    /// BR-9 resolve an ambiguous limit order by the client reference.
    async fn order_by_client_id(&self, client_order_id: &str) -> Result<Value, CommandDenial>;
    /// BR-9 resolve an ambiguous withdrawal by its client request reference.
    async fn withdrawal_by_request_id(
        &self,
        client_request_id: &str,
    ) -> Result<Value, CommandDenial>;
    /// BR-9 correlated progress read for a submitted request.
    async fn execution_progress(&self, client_request_id: &str) -> Result<Value, CommandDenial>;

    /// BR-9 progress of the current/active execution when the shipped client has
    /// no correlation id yet (the panel issues this read with no payload).
    /// Defaults to fail closed.
    async fn current_execution_progress(&self) -> Result<Value, CommandDenial> {
        Err(CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Web command backend is not configured.",
        ))
    }
}

/// Fail-closed default: every web-only operation is a determinate capability
/// denial (nothing can have committed because no backend is installed).
#[derive(Debug, Default)]
pub struct FailClosedWebContract;

impl FailClosedWebContract {
    fn denial() -> CommandDenial {
        CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Web command backend is not configured.",
        )
    }
}

#[async_trait]
impl WebContractBackend for FailClosedWebContract {
    async fn wallet_limits(&self) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
    async fn set_wallet_limits(
        &self,
        _limits: &Value,
        _idempotency_key: &str,
    ) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
    async fn order_by_id(&self, _order_id: &str) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
    async fn order_by_client_id(&self, _client_order_id: &str) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
    async fn withdrawal_by_request_id(
        &self,
        _client_request_id: &str,
    ) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
    async fn execution_progress(&self, _client_request_id: &str) -> Result<Value, CommandDenial> {
        Err(Self::denial())
    }
}

/// Composes the canonical command dispatcher with the web-only operations and
/// the BR-10/BR-12 response guarantees.
pub struct WebContractDispatcher {
    canonical: Arc<dyn CommandDispatcher>,
    web: Arc<dyn WebContractBackend>,
    /// Trusted capabilities. Web-only mutations (which never reach the canonical
    /// `authorize` core) are gated on the same `TRADING_ENABLED`/kill switch.
    capabilities: AgentCapabilities,
}

impl WebContractDispatcher {
    /// Fail-closed default: trading is disabled, so every web-only mutation is
    /// denied by the kill switch in addition to the fail-closed backend.
    pub fn new(canonical: Arc<dyn CommandDispatcher>, web: Arc<dyn WebContractBackend>) -> Self {
        Self::with_capabilities(
            canonical,
            web,
            AgentCapabilities::new(false, std::collections::HashSet::new(), 0),
        )
    }

    /// Compose with the caller's authoritative capabilities so the web-only
    /// mutations honour the shared trading gate.
    pub fn with_capabilities(
        canonical: Arc<dyn CommandDispatcher>,
        web: Arc<dyn WebContractBackend>,
        capabilities: AgentCapabilities,
    ) -> Self {
        Self {
            canonical,
            web,
            capabilities,
        }
    }

    /// Production default: canonical commands work but every web-only read/write
    /// fails closed.
    pub fn with_fail_closed_web(canonical: Arc<dyn CommandDispatcher>) -> Self {
        Self::new(canonical, Arc::new(FailClosedWebContract))
    }

    /// The `TRADING_ENABLED`/kill-switch gate shared with the canonical core.
    fn ensure_trading_enabled(&self) -> Result<(), CommandDenial> {
        if self.capabilities.trading_enabled {
            Ok(())
        } else {
            Err(CommandDenial::determinate(
                DenialCode::CapabilityMissing,
                "Trading is disabled by the global kill switch.",
            ))
        }
    }
}

#[async_trait]
impl CommandDispatcher for WebContractDispatcher {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        match request.op.as_str() {
            "get_wallet_limits" => self.web.wallet_limits().await,
            "set_wallet_limits" => {
                let key = request
                    .idempotency_key
                    .as_deref()
                    .filter(|key| !key.is_empty())
                    .ok_or_else(|| {
                        protocol("idempotency_key is required for set_wallet_limits.")
                    })?;
                // Web-only mutations do not travel through the canonical
                // `authorize` core, so the kill switch must be enforced here.
                self.ensure_trading_enabled()?;
                self.web.set_wallet_limits(&request.payload, key).await
            }
            "get_order" => {
                let order_id = required_string(request, "order_id")?;
                self.web.order_by_id(&order_id).await
            }
            "get_order_by_client_id" => {
                let client_order_id = required_string(request, "client_order_id")?;
                self.web.order_by_client_id(&client_order_id).await
            }
            "get_withdrawal_by_request_id" => {
                let client_request_id = required_string(request, "client_request_id")?;
                self.web.withdrawal_by_request_id(&client_request_id).await
            }
            "get_execution_progress" => match request.payload.get("client_request_id") {
                None | Some(Value::Null) => self.web.current_execution_progress().await,
                Some(Value::String(client_request_id)) if !client_request_id.trim().is_empty() => {
                    self.web.execution_progress(client_request_id).await
                }
                // A present but malformed id is a protocol error, never silently
                // served as a different (current) read.
                Some(_) => Err(protocol("client_request_id must be a non-empty string.")),
            },
            "place_limit_order" => {
                let value = self.canonical.dispatch(request).await?;
                normalize_limit_order_result(value)
            }
            "execute_market_order" => {
                let requested = requested_router(request)?;
                let value = self.canonical.dispatch(request).await?;
                normalize_execute_result(value, &requested)
            }
            _ => self.canonical.dispatch(request).await,
        }
    }
}

fn protocol(message: impl Into<String>) -> CommandDenial {
    CommandDenial::determinate(DenialCode::Protocol, message)
}

fn indeterminate(message: impl Into<String>) -> CommandDenial {
    CommandDenial::indeterminate(DenialCode::Unknown, message)
}

/// Read a required non-empty string field from the authenticated payload.
fn required_string(request: &CommandRequest, field: &str) -> Result<String, CommandDenial> {
    request
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| protocol(format!("{field} is required.")))
}

/// The routing source the client asked for, validated to the closed set.
fn requested_router(request: &CommandRequest) -> Result<String, CommandDenial> {
    match request
        .payload
        .get("router_preference")
        .and_then(Value::as_str)
    {
        Some("okx") => Ok("okx".to_string()),
        Some("local") => Ok("local".to_string()),
        _ => Err(protocol(
            "router_preference is required and must be okx or local.",
        )),
    }
}

/// BR-12: a limit-order success must identify the created order.
fn normalize_limit_order_result(mut value: Value) -> Result<Value, CommandDenial> {
    let order_id = value
        .get("order_id")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/order/order_id").and_then(Value::as_str))
        .filter(|order_id| !order_id.is_empty())
        .map(str::to_string);
    match order_id {
        Some(order_id) => {
            // Project the backend's own id to the top level the web contract
            // reads; the nested order document is preserved.
            if let Value::Object(map) = &mut value {
                map.insert("order_id".to_string(), Value::String(order_id));
                Ok(value)
            } else {
                Err(indeterminate("Limit order response was malformed."))
            }
        }
        None => Err(indeterminate(
            "Limit order response was missing an order id.",
        )),
    }
}

/// BR-10: an execute success must carry a matching source echo and an execution
/// id. A missing/mismatched echo or an `unknown` state is indeterminate so the
/// client keeps its idempotency key and never records a false success.
fn normalize_execute_result(value: Value, requested: &str) -> Result<Value, CommandDenial> {
    let state = value.pointer("/execution/state").and_then(Value::as_str);
    match state {
        Some("submitted") | Some("filled") => {}
        Some("unknown") => return Err(indeterminate("Execution outcome is unknown.")),
        _ => return Err(indeterminate("Execution response was malformed.")),
    }
    let echoed = value
        .get("router_source")
        .and_then(Value::as_str)
        .filter(|echoed| *echoed == requested)
        .ok_or_else(|| indeterminate("Execution source was not confirmed by the backend."))?;
    let _ = echoed;
    let execution_id = value
        .get("execution_id")
        .and_then(Value::as_str)
        .filter(|execution_id| !execution_id.is_empty())
        .ok_or_else(|| indeterminate("Execution response was missing an execution id."))?;
    let _ = execution_id;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    /// Canonical dispatcher stand-in returning a scripted value.
    struct CanonicalDispatcher {
        calls: Arc<AtomicUsize>,
        value: Result<Value, CommandDenial>,
    }

    #[async_trait]
    impl CommandDispatcher for CanonicalDispatcher {
        async fn dispatch(&self, _request: &CommandRequest) -> Result<Value, CommandDenial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.value.clone()
        }
    }

    fn request(json: &[u8]) -> CommandRequest {
        CommandRequest::parse(json).expect("request parses")
    }

    fn harness(value: Value) -> (WebContractDispatcher, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let canonical = Arc::new(CanonicalDispatcher {
            calls: calls.clone(),
            value: Ok(value),
        });
        (
            WebContractDispatcher::with_fail_closed_web(canonical),
            calls,
        )
    }

    #[tokio::test]
    async fn web_only_reads_fail_closed_by_default() {
        let (dispatcher, _) = harness(json!({}));
        for op in [
            r#"{"op":"get_wallet_limits","payload":{},"request_id":"r"}"#,
            r#"{"op":"get_order","payload":{"order_id":"o1"},"request_id":"r"}"#,
            r#"{"op":"get_order_by_client_id","payload":{"client_order_id":"c1"},"request_id":"r"}"#,
            r#"{"op":"get_withdrawal_by_request_id","payload":{"client_request_id":"w1"},"request_id":"r"}"#,
            r#"{"op":"get_execution_progress","payload":{"client_request_id":"e1"},"request_id":"r"}"#,
        ] {
            let denial = dispatcher
                .dispatch(&request(op.as_bytes()))
                .await
                .expect_err("fail closed");
            assert_eq!(denial.code, "capability_missing");
            assert!(!denial.retryable);
        }
    }

    #[tokio::test]
    async fn set_wallet_limits_requires_an_idempotency_key() {
        let (dispatcher, _) = harness(json!({}));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"set_wallet_limits","payload":{},"request_id":"r"}"#,
            ))
            .await
            .expect_err("missing key");
        assert_eq!(denial.code, "protocol");
    }

    /// Records whether the web-only backend was reached.
    #[derive(Default)]
    struct RecordingWebBackend {
        set_calls: Arc<AtomicUsize>,
        current_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WebContractBackend for RecordingWebBackend {
        async fn wallet_limits(&self) -> Result<Value, CommandDenial> {
            Ok(json!({}))
        }
        async fn set_wallet_limits(
            &self,
            _limits: &Value,
            _idempotency_key: &str,
        ) -> Result<Value, CommandDenial> {
            self.set_calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "applied": true }))
        }
        async fn order_by_id(&self, _order_id: &str) -> Result<Value, CommandDenial> {
            Ok(json!({}))
        }
        async fn order_by_client_id(&self, _client_order_id: &str) -> Result<Value, CommandDenial> {
            Ok(json!({}))
        }
        async fn withdrawal_by_request_id(
            &self,
            _client_request_id: &str,
        ) -> Result<Value, CommandDenial> {
            Ok(json!({}))
        }
        async fn execution_progress(
            &self,
            _client_request_id: &str,
        ) -> Result<Value, CommandDenial> {
            Ok(json!({}))
        }
        async fn current_execution_progress(&self) -> Result<Value, CommandDenial> {
            self.current_calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "state": "ACTIVE" }))
        }
    }

    fn capabilities(trading_enabled: bool) -> AgentCapabilities {
        AgentCapabilities::new(trading_enabled, std::collections::HashSet::new(), u64::MAX)
    }

    /// F1: a web-only write must honour the same kill switch as the canonical
    /// core even though it never travels through `agent_commands::authorize`.
    #[tokio::test]
    async fn set_wallet_limits_is_denied_while_trading_is_disabled() {
        let web = Arc::new(RecordingWebBackend::default());
        let canonical = Arc::new(CanonicalDispatcher {
            calls: Arc::new(AtomicUsize::new(0)),
            value: Ok(json!({})),
        });
        let dispatcher =
            WebContractDispatcher::with_capabilities(canonical, web.clone(), capabilities(false));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"set_wallet_limits","payload":{},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("kill switch");
        assert_eq!(denial.code, "capability_missing");
        assert!(!denial.retryable);
        assert_eq!(web.set_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn set_wallet_limits_reaches_the_backend_when_trading_is_enabled() {
        let web = Arc::new(RecordingWebBackend::default());
        let canonical = Arc::new(CanonicalDispatcher {
            calls: Arc::new(AtomicUsize::new(0)),
            value: Ok(json!({})),
        });
        let dispatcher =
            WebContractDispatcher::with_capabilities(canonical, web.clone(), capabilities(true));
        let value = dispatcher
            .dispatch(&request(
                br#"{"op":"set_wallet_limits","payload":{},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect("enabled");
        assert_eq!(value["applied"], true);
        assert_eq!(web.set_calls.load(Ordering::SeqCst), 1);
    }

    /// The shipped `get_execution_progress` read sends no payload; it must reach
    /// the current-progress read rather than a protocol denial.
    #[tokio::test]
    async fn get_execution_progress_without_a_correlation_id_reads_the_current_one() {
        let web = Arc::new(RecordingWebBackend::default());
        let canonical = Arc::new(CanonicalDispatcher {
            calls: Arc::new(AtomicUsize::new(0)),
            value: Ok(json!({})),
        });
        let dispatcher =
            WebContractDispatcher::with_capabilities(canonical, web.clone(), capabilities(true));
        let value = dispatcher
            .dispatch(&request(
                br#"{"op":"get_execution_progress","payload":null,"request_id":"r"}"#,
            ))
            .await
            .expect("current progress");
        assert_eq!(value["state"], "ACTIVE");
        assert_eq!(web.current_calls.load(Ordering::SeqCst), 1);
    }

    /// A present-but-malformed correlation id is a protocol error, never served
    /// silently as the current-progress read.
    #[tokio::test]
    async fn malformed_execution_progress_id_is_a_protocol_denial() {
        let web = Arc::new(RecordingWebBackend::default());
        let canonical = Arc::new(CanonicalDispatcher {
            calls: Arc::new(AtomicUsize::new(0)),
            value: Ok(json!({})),
        });
        let dispatcher =
            WebContractDispatcher::with_capabilities(canonical, web.clone(), capabilities(true));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"get_execution_progress","payload":{"client_request_id":123},"request_id":"r"}"#,
            ))
            .await
            .expect_err("malformed id");
        assert_eq!(denial.code, "protocol");
        assert_eq!(web.current_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_lookup_field_is_a_protocol_denial() {
        let (dispatcher, _) = harness(json!({}));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"get_order","payload":{},"request_id":"r"}"#,
            ))
            .await
            .expect_err("missing order id");
        assert_eq!(denial.code, "protocol");
    }

    #[tokio::test]
    async fn place_limit_projects_the_backend_order_id() {
        let (dispatcher, _) =
            harness(json!({ "order": { "order_id": "ord-7", "status": "ACTIVE" } }));
        let value = dispatcher
            .dispatch(&request(
                br#"{"op":"place_limit_order","payload":{},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect("order id present");
        assert_eq!(value["order_id"], "ord-7");
        assert_eq!(value["order"]["order_id"], "ord-7");
    }

    #[tokio::test]
    async fn place_limit_without_an_order_id_is_indeterminate() {
        let (dispatcher, _) = harness(json!({ "order": { "status": "ACTIVE" } }));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"place_limit_order","payload":{},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("no order id");
        assert_eq!(denial.code, "unknown");
        assert!(denial.retryable);
    }

    #[tokio::test]
    async fn execute_unknown_state_is_never_a_success() {
        let (dispatcher, _) = harness(json!({
            "execution": { "state": "unknown" },
            "execution_id": "i1",
            "router_source": "okx",
        }));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"execute_market_order","payload":{"router_preference":"okx"},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("unknown is indeterminate");
        assert_eq!(denial.code, "unknown");
        assert!(denial.retryable);
    }

    #[tokio::test]
    async fn execute_requires_a_matching_source_echo_and_execution_id() {
        let (dispatcher, _) = harness(json!({
            "execution": { "state": "submitted" },
            "execution_id": "i1",
            "router_source": "local",
        }));
        // Requested okx but the backend echoed local -> not attributable.
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"execute_market_order","payload":{"router_preference":"okx"},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("source mismatch");
        assert_eq!(denial.code, "unknown");

        // Missing execution id -> indeterminate, not a false success.
        let (dispatcher, _) = harness(json!({
            "execution": { "state": "submitted" },
            "router_source": "okx",
        }));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"execute_market_order","payload":{"router_preference":"okx"},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("missing execution id");
        assert_eq!(denial.code, "unknown");
    }

    #[tokio::test]
    async fn execute_with_a_matching_echo_and_id_succeeds() {
        let (dispatcher, _) = harness(json!({
            "execution": { "state": "submitted" },
            "execution_id": "i1",
            "router_source": "okx",
        }));
        let value = dispatcher
            .dispatch(&request(
                br#"{"op":"execute_market_order","payload":{"router_preference":"okx"},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect("attributable success");
        assert_eq!(value["execution_id"], "i1");
        assert_eq!(value["router_source"], "okx");
    }

    #[tokio::test]
    async fn execute_without_a_router_preference_fails_closed() {
        let (dispatcher, _) = harness(json!({
            "execution": { "state": "submitted" },
            "execution_id": "i1",
            "router_source": "okx",
        }));
        let denial = dispatcher
            .dispatch(&request(
                br#"{"op":"execute_market_order","payload":{},"request_id":"r","idempotency_key":"k"}"#,
            ))
            .await
            .expect_err("missing preference");
        assert_eq!(denial.code, "protocol");
    }
}
