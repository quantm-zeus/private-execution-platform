//! Pure JSON-RPC 2.0 / MCP dispatcher over an injected backend.
//!
//! The dispatcher is deliberately synchronous in its dependencies: it parses a
//! frame, decodes a command, obtains a trusted valuation from the backend, runs
//! [`agent_commands::authorize`], and only then calls the backend. It performs
//! no I/O of its own and emits only static/redacted text.

use std::collections::{btree_map::Entry, BTreeMap};
use std::fmt;

use agent_commands::{
    authorize, AgentCapabilities, AgentChannel, AgentCommand, AuthorizedCommand, DenyReason,
};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{json, Map, Value};

use crate::backend::{AgentBackend, BackendOutcome};
use crate::error::McpError;
use crate::schema;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Raw, lossless capture of a JSON object's fields.
type RawFields = BTreeMap<String, Box<RawValue>>;

/// Lossless JSON object capture that fails closed on duplicate keys.
///
/// `serde_json::Value` silently keeps the last value for a repeated key; an
/// ambiguous request must fail closed instead, so a repeated key is rejected.
struct RawObject(RawFields);

impl RawObject {
    fn into_map(self) -> RawFields {
        self.0
    }
}

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawObjectVisitor;

        impl<'de> Visitor<'de> for RawObjectVisitor {
            type Value = RawObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut fields = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    match fields.entry(key) {
                        Entry::Vacant(entry) => {
                            entry.insert(map.next_value::<Box<RawValue>>()?);
                        }
                        Entry::Occupied(_) => {
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                    }
                }
                Ok(RawObject(fields))
            }
        }

        deserializer.deserialize_map(RawObjectVisitor)
    }
}

/// Strictly parses a JSON object, rejecting non-objects and duplicate keys.
fn parse_object(raw: &str) -> Result<RawFields, ()> {
    serde_json::from_str::<RawObject>(raw)
        .map(RawObject::into_map)
        .map_err(|_| ())
}

/// JSON-RPC reply before the notification/id decision is applied.
enum Reply {
    /// The method is notification-only; emit no response.
    None,
    /// A JSON-RPC `result` value.
    Result(Value),
    /// A JSON-RPC `error` (code, static message).
    Error(i64, &'static str),
}

/// Final disposition of one frame.
enum Outcome {
    /// A notification: no response is emitted.
    NoResponse,
    /// A serialized response frame.
    Frame(String),
}

/// Pure MCP dispatcher over an injected backend and capability context.
pub struct McpServer<B: AgentBackend> {
    backend: B,
    capabilities: AgentCapabilities,
    /// Channel reported to `authorize` and the backend.
    ///
    /// `authorize` treats every channel identically (AC-4), but a backend or an
    /// audit sink may label commands by channel, so the value is explicit rather
    /// than hardcoded to MCP.
    channel: AgentChannel,
}

impl<B: AgentBackend> McpServer<B> {
    /// Builds a dispatcher from a trusted backend and capability context.
    ///
    /// The channel is [`AgentChannel::Mcp`]; use [`McpServer::for_channel`] for a
    /// different transport (for example Telegram) that shares this dispatcher.
    pub fn new(backend: B, capabilities: AgentCapabilities) -> Self {
        Self::for_channel(backend, capabilities, AgentChannel::Mcp)
    }

    /// Builds a dispatcher that labels commands as `channel`.
    pub fn for_channel(backend: B, capabilities: AgentCapabilities, channel: AgentChannel) -> Self {
        Self {
            backend,
            capabilities,
            channel,
        }
    }

    /// Handles one JSON-RPC frame (string in, string out).
    ///
    /// A frame without an `id` is a notification: it is processed (when its
    /// method has an effect) but the returned string is empty.
    pub async fn handle(&self, frame: &str) -> String {
        match self.dispatch(frame).await {
            Outcome::NoResponse => String::new(),
            Outcome::Frame(response) => response,
        }
    }

    /// Validates a notification frame without producing a response.
    ///
    /// This is a side-effect-free no-op: it acknowledges a well-formed
    /// notification (JSON-RPC 2.0, a `method`, and no `id`) and rejects anything
    /// else. It never calls the backend.
    pub async fn handle_notification(&self, frame: &str) -> Result<(), McpError> {
        let root =
            serde_json::from_str::<Box<RawValue>>(frame).map_err(|_| McpError::ParseError)?;
        let fields = parse_object(root.get()).map_err(|_| McpError::InvalidRequest)?;
        if fields.contains_key("id") || !json_rpc_version_ok(&fields) {
            return Err(McpError::InvalidRequest);
        }
        match fields
            .get("method")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
        {
            Some(_) => Ok(()),
            None => Err(McpError::InvalidRequest),
        }
    }

    async fn dispatch(&self, frame: &str) -> Outcome {
        let Ok(root) = serde_json::from_str::<Box<RawValue>>(frame) else {
            return Outcome::Frame(error_frame(Value::Null, PARSE_ERROR, "malformed request"));
        };
        let Ok(fields) = parse_object(root.get()) else {
            return Outcome::Frame(error_frame(Value::Null, INVALID_REQUEST, "invalid request"));
        };

        let has_id = fields.contains_key("id");
        // JSON-RPC 2.0: an untrustworthy `id` (object/array/boolean) is not
        // echoed; the error response carries `null` instead, so no raw request
        // value can leak through the id slot.
        let id_valid = id_is_valid(&fields);
        let id = if id_valid { request_id(&fields) } else { None };

        if !json_rpc_version_ok(&fields) || !id_valid {
            return finish(Reply::Error(INVALID_REQUEST, "invalid request"), has_id, id);
        }

        let Some(method) = fields
            .get("method")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
        else {
            return finish(Reply::Error(INVALID_REQUEST, "invalid request"), has_id, id);
        };

        let params = fields.get("params").map(|raw| &**raw);
        let reply = self.dispatch_method(&method, params).await;
        finish(reply, has_id, id)
    }

    async fn dispatch_method(&self, method: &str, params: Option<&RawValue>) -> Reply {
        match method {
            "initialize" => {
                if params.is_some_and(|params| parse_object(params.get()).is_err()) {
                    return Reply::Error(INVALID_PARAMS, "invalid params");
                }
                Reply::Result(initialize_result())
            }
            "notifications/initialized" => Reply::None,
            "tools/list" => {
                if params.is_some_and(|params| parse_object(params.get()).is_err()) {
                    return Reply::Error(INVALID_PARAMS, "invalid params");
                }
                Reply::Result(tools_list_result())
            }
            "tools/call" => self.call_tool(params).await,
            _ => Reply::Error(METHOD_NOT_FOUND, "unknown method"),
        }
    }

    async fn call_tool(&self, params: Option<&RawValue>) -> Reply {
        let Some(params) = params else {
            return Reply::Error(INVALID_PARAMS, "invalid params");
        };
        let Ok(param_fields) = parse_object(params.get()) else {
            return Reply::Error(INVALID_PARAMS, "invalid params");
        };
        let Some(name) = param_fields
            .get("name")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
        else {
            return Reply::Error(INVALID_PARAMS, "invalid params");
        };
        let arguments = match param_fields.get("arguments") {
            None => None,
            Some(raw) => {
                if parse_object(raw.get()).is_err() {
                    return Reply::Error(INVALID_PARAMS, "invalid params");
                }
                Some(&**raw)
            }
        };
        self.invoke_tool(&name, arguments).await
    }

    async fn invoke_tool(&self, name: &str, arguments: Option<&RawValue>) -> Reply {
        if !schema::is_known_tool(name) {
            return Reply::Result(tool_error("tool not found"));
        }
        let Some(command_json) = build_command_json(name, arguments) else {
            return Reply::Result(tool_error("malformed request"));
        };
        let Ok(command) = AgentCommand::parse(&command_json) else {
            return Reply::Result(tool_error("malformed request"));
        };

        // The valuation is backend-supplied and trusted; the dispatcher never
        // derives value from the request body.
        let valuation = self.backend.valuation_usd_micros(&command).await;
        match authorize(self.channel, command, &self.capabilities, valuation) {
            AuthorizedCommand::Denied(reason) => {
                Reply::Result(tool_error(deny_reason_name(reason)))
            }
            AuthorizedCommand::Read(command) => {
                let outcome = self
                    .backend
                    .execute(self.channel, AgentCommand::Read(command))
                    .await;
                Reply::Result(backend_result(outcome))
            }
            AuthorizedCommand::Trade(command) => {
                let outcome = self
                    .backend
                    .execute(self.channel, AgentCommand::Trade(command))
                    .await;
                Reply::Result(backend_result(outcome))
            }
        }
    }
}

/// Concatenates the tool tag with the exact raw `arguments` object.
///
/// The raw bytes are preserved so atomic `u128` amounts stay lossless and
/// duplicate keys remain detectable by the `agent-commands` decoder. A leading
/// `"tool"` in `arguments` therefore collides and fails closed.
fn build_command_json(tool: &str, arguments: Option<&RawValue>) -> Option<String> {
    let arguments = arguments.map(RawValue::get).unwrap_or("{}");
    let inner = arguments
        .trim()
        .strip_prefix('{')?
        .strip_suffix('}')?
        .trim();
    if inner.is_empty() {
        Some(format!(r#"{{"tool":"{tool}"}}"#))
    } else {
        Some(format!(r#"{{"tool":"{tool}",{inner}}}"#))
    }
}

fn json_rpc_version_ok(fields: &RawFields) -> bool {
    fields
        .get("jsonrpc")
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
        .is_some_and(|version| version == "2.0")
}

/// Builds a canonical JSON-RPC `tools/call` frame from a structured command
/// object of the shape `{"tool": "<name>", ...arguments}`.
///
/// This is the shared entry point for transports that receive a structured
/// command directly (for example the Telegram bot) and want the exact same
/// dispatcher path as an MCP client. The command object is parsed losslessly and
/// **top-level** duplicate keys are rejected (so a repeated `"tool"` or top-level
/// argument fails closed; a duplicate nested inside an argument object is left
/// for the `agent-commands` decoder, which rejects it) and the argument bytes are
/// spliced through verbatim, so atomic `u128` amounts stay lossless. Returns
/// `None` when the text is not a JSON object, has no non-empty string `"tool"`,
/// or repeats a top-level key.
pub fn tools_call_frame(command_json: &str) -> Option<String> {
    let fields = parse_object(command_json).ok()?;
    let tool = fields
        .get("tool")
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())?;
    if tool.is_empty() {
        return None;
    }
    let mut inner = String::new();
    for (key, raw) in &fields {
        if key == "tool" {
            continue;
        }
        if !inner.is_empty() {
            inner.push(',');
        }
        inner.push_str(&serde_json::to_string(key).ok()?);
        inner.push(':');
        inner.push_str(raw.get());
    }
    let name = serde_json::to_string(&tool).ok()?;
    Some(format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":{name},"arguments":{{{inner}}}}}}}"#
    ))
}

fn request_id(fields: &RawFields) -> Option<Value> {
    fields
        .get("id")
        .and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok())
}

fn id_is_valid(fields: &RawFields) -> bool {
    match fields.get("id") {
        None => true,
        Some(raw) => matches!(
            serde_json::from_str::<Value>(raw.get()),
            Ok(Value::Null | Value::String(_) | Value::Number(_))
        ),
    }
}

fn finish(reply: Reply, has_id: bool, id: Option<Value>) -> Outcome {
    match reply {
        Reply::None => Outcome::NoResponse,
        Reply::Result(result) if has_id => {
            Outcome::Frame(result_frame(&id.unwrap_or(Value::Null), result))
        }
        Reply::Result(_) => Outcome::NoResponse,
        Reply::Error(code, message) if has_id => {
            Outcome::Frame(error_frame(id.unwrap_or(Value::Null), code, message))
        }
        Reply::Error(_, _) => Outcome::NoResponse,
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "private-execution-platform",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

fn tools_list_result() -> Value {
    json!({ "tools": schema::tools() })
}

fn deny_reason_name(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::TradingDisabled => "TradingDisabled",
        DenyReason::ChainNotAllowed => "ChainNotAllowed",
        DenyReason::NotionalExceedsLimit => "NotionalExceedsLimit",
        DenyReason::ForbiddenOperation => "ForbiddenOperation",
    }
}

fn backend_result(outcome: BackendOutcome) -> Value {
    match outcome {
        BackendOutcome::Value(value) => tool_value(&value),
        BackendOutcome::Unavailable => tool_error("backend unavailable"),
        BackendOutcome::Denied => tool_error("command denied"),
    }
}

fn tool_value(value: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": to_json(value) }],
        "isError": false,
    })
}

fn tool_error(text: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true,
    })
}

fn result_frame(id: &Value, result: Value) -> String {
    let mut object = Map::new();
    object.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
    object.insert("id".to_string(), id.clone());
    object.insert("result".to_string(), result);
    to_json(&Value::Object(object))
}

fn error_frame(id: Value, code: i64, message: &'static str) -> String {
    let mut error = Map::new();
    error.insert("code".to_string(), json!(code));
    error.insert("message".to_string(), Value::String(message.to_string()));
    let mut object = Map::new();
    object.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
    object.insert("id".to_string(), id);
    object.insert("error".to_string(), Value::Object(error));
    to_json(&Value::Object(object))
}

fn to_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}
