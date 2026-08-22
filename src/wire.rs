//! The Paykit Server wire contract the Lock Server speaks
//! (locks-server `paykit_http_client.rs`), plus the buyer-facing
//! checkout-session surface this gateway adds.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// `POST /invoices` body sent by the Lock Server on proof-bundle submission.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvoiceRequest {
    pub bundle_id: String,
    pub lock_resource: String,
    pub reader: String,
}

/// `POST /transactions/status` body polled by the Lock Server worker.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub creator: String,
    pub bundle_id: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StatusKind {
    Undetected,
    Detected,
    Confirmed,
}

/// The status shape `PaykitPaymentVerifier` consumes upstream.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub status: StatusKind,
    pub confirmations: u32,
    pub amount_matched: bool,
}

/// Buyer-facing `POST /checkout-sessions` request. The bundle id is bearer
/// material (the marketplace already treats it as such and seals it at rest).
#[derive(Clone, Debug, Deserialize)]
pub struct CheckoutSessionRequest {
    pub creator: String,
    pub bundle_id: String,
    /// Optional processor choice (`stripe` | `paypal`), honored only while
    /// the correlation is not yet bound to a processor; afterwards a
    /// mismatch is a 409. Defaults to the deployment's default processor.
    #[serde(default)]
    pub processor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckoutSessionResponse {
    pub checkout_url: String,
    pub processor: &'static str,
    /// Unix seconds when the processor session expires (re-call to re-mint).
    pub expires_at: i64,
}

const MAX_ID_LENGTH: usize = 128;
const MAX_RESOURCE_LENGTH: usize = 512;

/// Splits an addressed lock resource (`pubky<z32>/pub/locks.app/<id>.json`)
/// into (creator app key, path). Light validation only: the gateway must not
/// be stricter than the services behind it; deep validation stays upstream.
pub fn parse_lock_resource(lock_resource: &str) -> Result<(&str, &str), ApiError> {
    if lock_resource.is_empty() || lock_resource.len() > MAX_RESOURCE_LENGTH {
        return Err(ApiError::InvalidRequest);
    }
    let slash = lock_resource.find('/').ok_or(ApiError::InvalidRequest)?;
    let (creator, path) = lock_resource.split_at(slash);
    if creator.is_empty() || !path.starts_with("/pub/") {
        return Err(ApiError::InvalidRequest);
    }
    Ok((creator, path))
}

pub fn validate_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > MAX_ID_LENGTH
        || !value.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lock_resource_into_creator_and_path() {
        let (creator, path) = parse_lock_resource(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/locks.app/abc.json",
        )
        .unwrap();
        assert_eq!(
            creator,
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy"
        );
        assert_eq!(path, "/pub/locks.app/abc.json");
    }

    #[test]
    fn rejects_resources_outside_pub() {
        assert!(parse_lock_resource("pubkyabc/priv/locks.app/abc.json").is_err());
        assert!(parse_lock_resource("no-slash").is_err());
        assert!(parse_lock_resource("").is_err());
    }

    #[test]
    fn status_serializes_the_exact_upstream_shape() {
        let status = TransactionStatus {
            status: StatusKind::Detected,
            confirmations: 0,
            amount_matched: true,
        };
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"status":"detected","confirmations":0,"amount_matched":true}"#
        );
    }
}
