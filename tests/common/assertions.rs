use serde_json::Value;

/// Assert the response body matches the standard error envelope:
/// { "error": { "code": "...", "message": "..." } }
pub fn assert_error_envelope(body: &Value) -> &str {
    assert!(
        body["error"].is_object(),
        "Response missing 'error' object: {body}"
    );
    let error = &body["error"];
    assert!(
        error["code"].is_string(),
        "Error missing 'code' string: {body}"
    );
    assert!(
        error["message"].is_string(),
        "Error missing 'message' string: {body}"
    );
    error["code"]
        .as_str()
        .unwrap_or_else(|| panic!("Error code is not a string: {body}"))
}

pub fn assert_error_code(body: &Value, expected_code: &str) {
    let actual = assert_error_envelope(body);
    assert_eq!(
        actual, expected_code,
        "Expected error code '{expected_code}' but got '{actual}'. Body: {body}"
    );
}
