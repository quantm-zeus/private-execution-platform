//! Opaque internal relay gRPC contract.
//!
//! This crate intentionally carries no application semantics. Callers exchange
//! bounded ciphertext payloads only. All validation helpers fail closed before
//! a message can reach a service implementation.

use tonic::{Response, Status};

/// Hard upper bound for any ciphertext payload exchanged over the internal
/// relay contract.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

include!(concat!(env!("OUT_DIR"), "/evergreen.opaque.v1.rs"));

/// Validates a payload for the opaque relay contract.
pub fn validate_payload(payload: &[u8]) -> Result<(), PayloadError> {
    if payload.is_empty() {
        return Err(PayloadError::Empty);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(PayloadError::TooLarge);
    }
    Ok(())
}

/// Validates a unary relay request, including route presence.
pub fn validate_relay_request(request: &RelayRequest) -> Result<(), RequestError> {
    match Route::try_from(request.route) {
        Ok(Route::Bootstrap | Route::Sync | Route::Blob) => {}
        Ok(Route::Unspecified) | Err(_) => return Err(RequestError::InvalidRoute),
    }
    validate_payload(&request.ciphertext).map_err(RequestError::Payload)
}

/// Payload-level validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("ciphertext payload is empty")]
    Empty,
    #[error("ciphertext payload exceeds the 1 MiB contract bound")]
    TooLarge,
}

/// Unary request validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("relay route is invalid")]
    InvalidRoute,
    #[error(transparent)]
    Payload(#[from] PayloadError),
}

impl From<RequestError> for Status {
    fn from(value: RequestError) -> Self {
        match value {
            RequestError::InvalidRoute => Status::invalid_argument(value.to_string()),
            RequestError::Payload(_) => Status::out_of_range(value.to_string()),
        }
    }
}

/// Generated server trait for the unary relay service.
pub mod relay_service {
    pub use super::relay_service_server::{RelayService, RelayServiceServer};
}

/// Generated server trait for the bidirectional relay stream.
pub mod relay_stream_service {
    pub use super::relay_stream_service_server::{RelayStreamService, RelayStreamServiceServer};
}

pub type RelayResponseResult = Result<Response<RelayResponse>, Status>;
pub type StreamFrameResult = Result<StreamFrame, Status>;

#[cfg(test)]
mod tests {
    use super::*;

    fn request(route: i32, size: usize) -> RelayRequest {
        RelayRequest {
            route,
            ciphertext: vec![0xA5; size],
        }
    }

    #[test]
    fn payload_bounds_are_fail_closed() {
        assert_eq!(validate_payload(&[]), Err(PayloadError::Empty));
        assert!(validate_payload(&vec![0u8; MAX_PAYLOAD_BYTES]).is_ok());
        assert_eq!(
            validate_payload(&vec![0u8; MAX_PAYLOAD_BYTES + 1]),
            Err(PayloadError::TooLarge)
        );
    }

    #[test]
    fn unary_route_validation_rejects_unspecified_and_unknown() {
        assert_eq!(
            validate_relay_request(&request(Route::Unspecified as i32, 1)),
            Err(RequestError::InvalidRoute)
        );
        assert_eq!(
            validate_relay_request(&request(9_999, 1)),
            Err(RequestError::InvalidRoute)
        );
    }

    #[test]
    fn unary_route_validation_accepts_only_neutral_routes() {
        for route in [Route::Bootstrap, Route::Sync, Route::Blob] {
            assert!(validate_relay_request(&request(route as i32, 1)).is_ok());
        }
    }

    #[test]
    fn generated_route_numeric_contract_is_stable() {
        assert_eq!(Route::try_from(0), Ok(Route::Unspecified));
        assert_eq!(Route::try_from(1), Ok(Route::Bootstrap));
        assert_eq!(Route::try_from(2), Ok(Route::Sync));
        assert_eq!(Route::try_from(3), Ok(Route::Blob));
        assert!(Route::try_from(4).is_err());
    }
}
