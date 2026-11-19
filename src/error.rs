//! Stable, versioned errors crossing the Remote wire/UI boundary.
//!
//! Producers should construct an [`ErrorEnvelope`] with one of the registered
//! codes below.  Human-readable text belongs in the local UI catalogue and is
//! never used for control flow.

use crate::rendezvous_proto::{ErrorCategory, ErrorCode, ErrorEnvelope};

pub const ERROR_SCHEMA_VERSION: u32 = 1;
pub const MAX_ERROR_DETAILS_BYTES: usize = 1024;
pub const MAX_CORRELATION_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorContext {
    Login,
    FileTransfer,
    Close,
    HttpProxy,
    Terminal,
}

pub fn envelope(
    category: ErrorCategory,
    code: ErrorCode,
    retryable: bool,
    display_key: &'static str,
) -> ErrorEnvelope {
    ErrorEnvelope {
        schema_version: ERROR_SCHEMA_VERSION,
        category: category.into(),
        code: code.into(),
        retryable,
        display_key: display_key.to_owned(),
        ..Default::default()
    }
}

pub fn with_details(mut error: ErrorEnvelope, details: impl AsRef<str>) -> ErrorEnvelope {
    error.details = bounded(details.as_ref(), MAX_ERROR_DETAILS_BYTES);
    error
}

pub fn with_correlation_id(
    mut error: ErrorEnvelope,
    correlation_id: impl AsRef<str>,
) -> ErrorEnvelope {
    error.correlation_id = bounded(correlation_id.as_ref(), MAX_CORRELATION_ID_BYTES);
    error
}

pub fn bounded(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

pub fn is_valid(error: &ErrorEnvelope) -> bool {
    let Ok(code) = error.code.enum_value() else {
        return false;
    };
    if code == ErrorCode::ERROR_CODE_UNSPECIFIED {
        return false;
    }
    let canonical = for_code(code);
    error.schema_version == ERROR_SCHEMA_VERSION
        && error.category == canonical.category
        && error.retryable == canonical.retryable
        && error.display_key == canonical.display_key
        && error.display_key.len() <= 128
        && error.details.len() <= MAX_ERROR_DETAILS_BYTES
        && error.correlation_id.len() <= MAX_CORRELATION_ID_BYTES
        && !error.display_key.chars().any(char::is_control)
        && !error.details.chars().any(char::is_control)
        && !error.correlation_id.chars().any(char::is_control)
}

/// Validate both the envelope and the message domain carrying it. A globally
/// registered code is not automatically meaningful in every protobuf field.
pub fn is_valid_for(error: &ErrorEnvelope, context: ErrorContext) -> bool {
    if !is_valid(error) {
        return false;
    }
    let Ok(code) = error.code.enum_value() else {
        return false;
    };
    match context {
        ErrorContext::Login => !matches!(
            code,
            ErrorCode::FILE_OPERATION_FAILED | ErrorCode::HTTP_PROXY_FAILED
        ),
        ErrorContext::FileTransfer => matches!(
            code,
            ErrorCode::CONNECTION_TIMEOUT
                | ErrorCode::CONNECTION_RESET
                | ErrorCode::CONNECTION_CLOSED
                | ErrorCode::PERMISSION_DENIED
                | ErrorCode::CONFLICT
                | ErrorCode::CANCELLED
                | ErrorCode::NOT_FOUND
                | ErrorCode::FILE_OPERATION_FAILED
                | ErrorCode::PROTOCOL_MISMATCH
                | ErrorCode::INTERNAL_FAILURE
        ),
        ErrorContext::Close => matches!(
            code,
            ErrorCode::CONNECTION_OFFLINE
                | ErrorCode::CONNECTION_TIMEOUT
                | ErrorCode::CONNECTION_RESET
                | ErrorCode::CONNECTION_CLOSED
                | ErrorCode::PERMISSION_DENIED
                | ErrorCode::CONFLICT
                | ErrorCode::CANCELLED
                | ErrorCode::PROTOCOL_MISMATCH
                | ErrorCode::INTERNAL_FAILURE
        ),
        ErrorContext::HttpProxy => matches!(
            code,
            ErrorCode::CONNECTION_OFFLINE
                | ErrorCode::CONNECTION_TIMEOUT
                | ErrorCode::CONNECTION_RESET
                | ErrorCode::CONNECTION_CLOSED
                | ErrorCode::PERMISSION_DENIED
                | ErrorCode::HTTP_PROXY_FAILED
                | ErrorCode::PROTOCOL_MISMATCH
                | ErrorCode::INTERNAL_FAILURE
                | ErrorCode::RATE_LIMITED
                | ErrorCode::SERVICE_BUSY
        ),
        ErrorContext::Terminal => matches!(
            code,
            ErrorCode::CONNECTION_CLOSED
                | ErrorCode::PERMISSION_DENIED
                | ErrorCode::CONFLICT
                | ErrorCode::CANCELLED
                | ErrorCode::NOT_FOUND
                | ErrorCode::PROTOCOL_MISMATCH
                | ErrorCode::INTERNAL_FAILURE
                | ErrorCode::SERVICE_BUSY
        ),
    }
}

/// Convert a stable error code to its contract defaults. Producers may add
/// bounded details/correlation after calling this helper.
pub fn for_code(code: ErrorCode) -> ErrorEnvelope {
    use ErrorCategory::*;
    let (category, retryable, display_key) = match code {
        ErrorCode::PASSWORD_REQUIRED => (ERROR_CATEGORY_AUTHENTICATION, true, "password_required"),
        ErrorCode::PASSWORD_INVALID => (ERROR_CATEGORY_AUTHENTICATION, true, "password_invalid"),
        ErrorCode::TWO_FACTOR_REQUIRED => {
            (ERROR_CATEGORY_AUTHENTICATION, true, "two_factor_required")
        }
        ErrorCode::TWO_FACTOR_INVALID => {
            (ERROR_CATEGORY_AUTHENTICATION, true, "two_factor_invalid")
        }
        ErrorCode::NO_PASSWORD_ACCESS => (ERROR_CATEGORY_AUTHORIZATION, true, "no_password_access"),
        ErrorCode::WAYLAND_UNSUPPORTED => (ERROR_CATEGORY_PLATFORM, true, "wayland_unsupported"),
        ErrorCode::DISPLAY_SERVER_UNSUPPORTED => {
            (ERROR_CATEGORY_PLATFORM, true, "display_server_unsupported")
        }
        ErrorCode::CONNECTION_OFFLINE => (ERROR_CATEGORY_NETWORK, false, "connection_offline"),
        ErrorCode::CONNECTION_TIMEOUT => (ERROR_CATEGORY_NETWORK, true, "connection_timeout"),
        ErrorCode::CONNECTION_RESET => (ERROR_CATEGORY_NETWORK, true, "connection_reset"),
        ErrorCode::CONNECTION_CLOSED => (ERROR_CATEGORY_NETWORK, false, "connection_closed"),
        ErrorCode::PERMISSION_DENIED => (ERROR_CATEGORY_AUTHORIZATION, false, "permission_denied"),
        ErrorCode::CONFLICT => (ERROR_CATEGORY_STATE, false, "conflict"),
        ErrorCode::CANCELLED => (ERROR_CATEGORY_STATE, false, "cancelled"),
        ErrorCode::NOT_FOUND => (ERROR_CATEGORY_STATE, false, "not_found"),
        ErrorCode::FILE_OPERATION_FAILED => {
            (ERROR_CATEGORY_FILE_TRANSFER, false, "file_operation_failed")
        }
        ErrorCode::HTTP_PROXY_FAILED => (ERROR_CATEGORY_NETWORK, true, "http_proxy_failed"),
        ErrorCode::PROTOCOL_MISMATCH => (ERROR_CATEGORY_PROTOCOL, false, "protocol_mismatch"),
        ErrorCode::DESKTOP_SESSION_NOT_READY => {
            (ERROR_CATEGORY_PLATFORM, true, "desktop_session_not_ready")
        }
        ErrorCode::DESKTOP_XSESSION_FAILED => {
            (ERROR_CATEGORY_PLATFORM, true, "desktop_xsession_failed")
        }
        ErrorCode::DESKTOP_SESSION_ANOTHER_USER => (
            ERROR_CATEGORY_PLATFORM,
            false,
            "desktop_session_another_user",
        ),
        ErrorCode::DESKTOP_XORG_NOT_FOUND => {
            (ERROR_CATEGORY_PLATFORM, true, "desktop_xorg_not_found")
        }
        ErrorCode::DESKTOP_NOT_FOUND => (ERROR_CATEGORY_PLATFORM, true, "desktop_no_desktop"),
        ErrorCode::DESKTOP_SESSION_PASSWORD_REQUIRED => (
            ERROR_CATEGORY_AUTHENTICATION,
            true,
            "desktop_session_password_required",
        ),
        ErrorCode::DESKTOP_SESSION_PASSWORD_INVALID => (
            ERROR_CATEGORY_AUTHENTICATION,
            true,
            "desktop_session_password_invalid",
        ),
        ErrorCode::RATE_LIMITED => (ERROR_CATEGORY_NETWORK, true, "rate_limited"),
        ErrorCode::SERVICE_BUSY => (ERROR_CATEGORY_NETWORK, true, "service_busy"),
        ErrorCode::INTERNAL_FAILURE | ErrorCode::ERROR_CODE_UNSPECIFIED => {
            (ERROR_CATEGORY_INTERNAL, false, "internal_failure")
        }
    };
    envelope(category, code, retryable, display_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::{Enum as _, Message as _};
    use std::collections::HashSet;

    #[test]
    fn envelope_is_versioned_and_bounded() {
        let error = with_correlation_id(
            with_details(
                envelope(
                    ErrorCategory::ERROR_CATEGORY_NETWORK,
                    ErrorCode::CONNECTION_TIMEOUT,
                    true,
                    "connection_timeout",
                ),
                "x".repeat(MAX_ERROR_DETAILS_BYTES + 10),
            ),
            "trace-1",
        );
        assert!(is_valid(&error));
        assert_eq!(error.schema_version, ERROR_SCHEMA_VERSION);
        assert_eq!(error.details.len(), MAX_ERROR_DETAILS_BYTES);
    }

    #[test]
    fn rejects_unknown_version_and_control_data() {
        let mut error = for_code(ErrorCode::PASSWORD_INVALID);
        assert!(is_valid(&error));
        error.schema_version += 1;
        assert!(!is_valid(&error));
        error.schema_version = ERROR_SCHEMA_VERSION;
        error.display_key.push('\n');
        assert!(!is_valid(&error));
    }

    #[test]
    fn rejects_unknown_code_and_semantic_tampering() {
        let mut error = for_code(ErrorCode::CONNECTION_TIMEOUT);
        error.code = protobuf::EnumOrUnknown::from_i32(99_999);
        assert!(!is_valid(&error));

        let mut error = for_code(ErrorCode::CONNECTION_TIMEOUT);
        error.retryable = false;
        assert!(!is_valid(&error));

        let mut error = for_code(ErrorCode::PASSWORD_INVALID);
        error.display_key = "Wrong Password".to_owned();
        assert!(!is_valid(&error));

        let mut error = for_code(ErrorCode::PASSWORD_INVALID);
        error.category = ErrorCategory::ERROR_CATEGORY_NETWORK.into();
        assert!(!is_valid(&error));

        let mut error = for_code(ErrorCode::PASSWORD_INVALID);
        error.correlation_id = "trace\nforged".to_owned();
        assert!(!is_valid(&error));
    }

    #[test]
    fn every_registered_code_has_a_unique_valid_round_trip_contract() {
        let mut numeric_codes = HashSet::new();
        let mut display_keys = HashSet::new();

        for &code in ErrorCode::VALUES {
            assert!(
                numeric_codes.insert(code.value()),
                "duplicate code {code:?}"
            );
            let error = for_code(code);

            if code == ErrorCode::ERROR_CODE_UNSPECIFIED {
                assert!(!is_valid(&error));
                continue;
            }

            assert!(is_valid(&error), "invalid defaults for {code:?}");
            assert!(
                display_keys.insert(error.display_key.clone()),
                "duplicate display key for {code:?}"
            );
            let encoded = error.write_to_bytes().expect("encode error envelope");
            let decoded = ErrorEnvelope::parse_from_bytes(&encoded).expect("decode error envelope");
            assert_eq!(decoded, error, "wire drift for {code:?}");
            assert!(is_valid(&decoded), "invalid decoded envelope for {code:?}");
        }

        assert_eq!(display_keys.len() + 1, ErrorCode::VALUES.len());
    }

    #[test]
    fn rejects_registered_codes_in_the_wrong_message_domain() {
        assert!(is_valid_for(
            &for_code(ErrorCode::PASSWORD_INVALID),
            ErrorContext::Login
        ));
        assert!(!is_valid_for(
            &for_code(ErrorCode::FILE_OPERATION_FAILED),
            ErrorContext::Login
        ));
        assert!(is_valid_for(
            &for_code(ErrorCode::FILE_OPERATION_FAILED),
            ErrorContext::FileTransfer
        ));
        assert!(!is_valid_for(
            &for_code(ErrorCode::HTTP_PROXY_FAILED),
            ErrorContext::FileTransfer
        ));
        assert!(is_valid_for(
            &for_code(ErrorCode::RATE_LIMITED),
            ErrorContext::HttpProxy
        ));
        assert!(!is_valid_for(
            &for_code(ErrorCode::PASSWORD_REQUIRED),
            ErrorContext::HttpProxy
        ));
    }
}
