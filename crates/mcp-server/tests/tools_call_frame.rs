//! P59: the shared `tools_call_frame` builder preserves raw argument bytes and
//! fails closed on ambiguous input.

use mcp_server::tools_call_frame;
use serde_json::Value;

#[test]
fn builds_a_tools_call_frame_preserving_raw_arguments() {
    let frame = tools_call_frame(r#"{"tool":"get_orders","status":"active"}"#).expect("frame");
    let value: Value = serde_json::from_str(&frame).expect("json");
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["method"], "tools/call");
    assert_eq!(value["params"]["name"], "get_orders");
    assert_eq!(value["params"]["arguments"]["status"], "active");
    assert!(value["params"]["arguments"].get("tool").is_none());
}

#[test]
fn preserves_u128_amount_digits_verbatim() {
    let digits = "340282366920938463463374607431768211455";
    let text = format!(r#"{{"tool":"get_quote","amount":{{"unit":"token","value":{digits}}}}}"#);
    let frame = tools_call_frame(&text).expect("frame");
    // The raw digits survive into the frame even though a plain `Value` parse
    // would round them to f64; `AgentCommand::parse` reads them losslessly.
    assert!(frame.contains(digits));
}

#[test]
fn rejects_duplicate_keys_missing_tool_and_non_objects() {
    assert!(tools_call_frame(r#"{"tool":"get_orders","status":"a","status":"b"}"#).is_none());
    assert!(tools_call_frame(r#"{"tool":"get_orders","tool":"get_portfolio"}"#).is_none());
    assert!(tools_call_frame(r#"{"status":"active"}"#).is_none());
    assert!(tools_call_frame(r#"{"tool":123}"#).is_none());
    assert!(tools_call_frame(r#"{"tool":""}"#).is_none());
    assert!(tools_call_frame("not json").is_none());
    assert!(tools_call_frame(r#"["array"]"#).is_none());
    assert!(tools_call_frame("{}").is_none());
}
