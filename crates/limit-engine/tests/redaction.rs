//! Redaction roster: no error variant may expose a payload.

use limit_engine::LimitEngineError;

#[test]
fn error_roster_is_complete() {
    assert_eq!(LimitEngineError::ALL.len(), 20);
    let mut names: Vec<String> = LimitEngineError::ALL
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 20, "error roster contains duplicates");
}

#[test]
fn every_error_variant_is_payload_free() {
    for error in LimitEngineError::ALL {
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(!display.is_empty(), "empty display for {debug}");
        assert!(
            !display.chars().any(|c| c.is_ascii_digit()),
            "display for {debug} leaked a number: {display}"
        );
        assert!(
            !debug.chars().any(|c| c.is_ascii_digit()),
            "debug leaked a number: {debug}"
        );
        assert!(
            !display.contains("0x") && !debug.contains("0x"),
            "error leaked a hex reference: {debug}"
        );
        assert!(
            !display.contains('(') && !debug.contains('('),
            "error debug carries a payload: {debug}"
        );
        assert!(
            !display.contains('{') && !debug.contains('{'),
            "error debug carries a payload: {debug}"
        );
    }
}
