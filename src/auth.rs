//! Signed-request verification mirroring paykit-server `http/auth.rs`
//! semantics exactly, because the Lock Server is the same caller either way:
//!
//! 1. exactly one `X-Paykit-Signature` header;
//! 2. the value is base64url-no-pad and canonically encoded (re-encoding the
//!    decoded 64 bytes must reproduce the header string);
//! 3. the ed25519 signature verifies over the RAW request body bytes against
//!    the single pinned Lock Server public key;
//! 4. the body must be canonical JSON (RFC 8785): re-canonicalizing the parsed
//!    value must reproduce the raw bytes exactly;
//! 5. deserialization is strict — unknown fields reject the request.

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

pub const SIGNATURE_HEADER: &str = "x-paykit-signature";

pub fn verify_signature(
    trusted_key: &VerifyingKey,
    headers: &HeaderMap,
    raw_body: &[u8],
) -> Result<(), ApiError> {
    let signatures = headers.get_all(SIGNATURE_HEADER);
    if signatures.iter().count() != 1 {
        return Err(ApiError::InvalidSignature);
    }
    let encoded = signatures
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidSignature)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| ApiError::InvalidSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ApiError::InvalidSignature)?;
    if URL_SAFE_NO_PAD.encode(signature) != encoded {
        return Err(ApiError::InvalidSignature);
    }
    trusted_key
        .verify(raw_body, &Signature::from_bytes(&signature))
        .map_err(|_| ApiError::InvalidSignature)
}

/// Strict canonical-JSON parse: the raw bytes must already be RFC 8785
/// canonical form, and the payload type must consume every field.
pub fn parse_canonical_strict<T>(raw_body: &[u8]) -> Result<T, ApiError>
where
    T: DeserializeOwned,
{
    let value: serde_json::Value =
        serde_json::from_slice(raw_body).map_err(|_| ApiError::InvalidRequest)?;
    let canonical =
        serde_json_canonicalizer::to_vec(&value).map_err(|_| ApiError::InvalidRequest)?;
    if canonical != raw_body {
        return Err(ApiError::InvalidRequest);
    }
    serde_json::from_slice(raw_body).map_err(|_| ApiError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        bundle_id: String,
        creator: String,
    }

    fn keypair() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn signed_headers(key: &SigningKey, body: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            SIGNATURE_HEADER,
            HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes())).unwrap(),
        );
        headers
    }

    #[test]
    fn accepts_valid_signature_over_raw_body() {
        let key = keypair();
        let body = br#"{"bundle_id":"000G40R40M30E209185GR38E1W","creator":"pubkyabc"}"#;
        let headers = signed_headers(&key, body);
        assert!(verify_signature(&key.verifying_key(), &headers, body).is_ok());
    }

    #[test]
    fn rejects_missing_signature() {
        let key = keypair();
        assert_eq!(
            verify_signature(&key.verifying_key(), &HeaderMap::new(), b"{}"),
            Err(ApiError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_duplicate_signature_headers() {
        let key = keypair();
        let body = b"{}";
        let mut headers = signed_headers(&key, body);
        headers.append(
            SIGNATURE_HEADER,
            headers.get(SIGNATURE_HEADER).unwrap().clone(),
        );
        assert_eq!(
            verify_signature(&key.verifying_key(), &headers, body),
            Err(ApiError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_signature_from_untrusted_key() {
        let key = keypair();
        let other = SigningKey::from_bytes(&[7_u8; 32]);
        let body = b"{}";
        let headers = signed_headers(&other, body);
        assert_eq!(
            verify_signature(&key.verifying_key(), &headers, body),
            Err(ApiError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let key = keypair();
        let headers = signed_headers(&key, b"{\"a\":1}");
        assert_eq!(
            verify_signature(&key.verifying_key(), &headers, b"{\"a\":2}"),
            Err(ApiError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_padded_base64_signature_encoding() {
        let key = keypair();
        let body = b"{}";
        let sig = key.sign(body).to_bytes();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(sig);
        let mut headers = HeaderMap::new();
        headers.insert(SIGNATURE_HEADER, HeaderValue::from_str(&padded).unwrap());
        assert_eq!(
            verify_signature(&key.verifying_key(), &headers, body),
            Err(ApiError::InvalidSignature)
        );
    }

    #[test]
    fn parses_strict_canonical_body() {
        let body = br#"{"bundle_id":"B","creator":"C"}"#;
        let parsed: Probe = parse_canonical_strict(body).unwrap();
        assert_eq!(
            parsed,
            Probe {
                bundle_id: "B".into(),
                creator: "C".into()
            }
        );
    }

    #[test]
    fn rejects_non_canonical_key_order() {
        let body = br#"{"creator":"C","bundle_id":"B"}"#;
        assert!(parse_canonical_strict::<Probe>(body).is_err());
    }

    #[test]
    fn rejects_non_canonical_whitespace() {
        let body = br#"{"bundle_id": "B", "creator": "C"}"#;
        assert!(parse_canonical_strict::<Probe>(body).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let body = br#"{"bundle_id":"B","creator":"C","extra":true}"#;
        assert!(parse_canonical_strict::<Probe>(body).is_err());
    }
}
