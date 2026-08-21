//! Content-lock retrieval and criterion extraction. Mirrors paykit-server's
//! `PubkyLockFetcher` (public homeserver read via the Pubky SDK, size-capped,
//! timeout-bounded) and its `extract_terms` criterion parse, generalized to
//! carry the asset through instead of pinning it to BTC.

use std::time::Duration;

use async_trait::async_trait;
use pubky::errors::RequestError;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFetchError {
    NotFound,
    Unavailable,
    Invalid,
}

/// The payment criterion of a content lock, as authored at lock creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockCriterion {
    pub asset: String,
    /// Positive decimal integer string in the asset's minor units
    /// (sats for BTC, cents for USD).
    pub amount: String,
    pub recipient_pubky: String,
}

#[async_trait]
pub trait CriterionSource: Send + Sync {
    async fn criterion(&self, lock_resource: &str) -> Result<LockCriterion, LockFetchError>;
}

/// Extracts the `paykit-payment` criterion from a raw content-lock document.
/// Field semantics follow locks-core `validate_paykit_payment_params`:
/// `asset` any non-empty string, `amount` positive decimal integer string,
/// `recipient_pubky` present.
pub fn parse_criterion(document: &[u8]) -> Result<LockCriterion, LockFetchError> {
    let lock: Value = serde_json::from_slice(document).map_err(|_| LockFetchError::Invalid)?;
    let criteria = lock
        .get("criteria")
        .and_then(Value::as_array)
        .ok_or(LockFetchError::Invalid)?;
    let criterion = criteria
        .iter()
        .find(|criterion| {
            criterion.get("verifier_type").and_then(Value::as_str) == Some("paykit-payment")
        })
        .ok_or(LockFetchError::Invalid)?;
    let params = criterion.get("params").ok_or(LockFetchError::Invalid)?;
    let asset = params
        .get("asset")
        .and_then(Value::as_str)
        .filter(|asset| !asset.is_empty())
        .ok_or(LockFetchError::Invalid)?;
    let amount = params
        .get("amount")
        .and_then(Value::as_str)
        .ok_or(LockFetchError::Invalid)?;
    if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LockFetchError::Invalid);
    }
    let recipient = params
        .get("recipient_pubky")
        .and_then(Value::as_str)
        .filter(|recipient| !recipient.is_empty())
        .ok_or(LockFetchError::Invalid)?;
    Ok(LockCriterion {
        asset: asset.to_owned(),
        amount: amount.to_owned(),
        recipient_pubky: recipient.to_owned(),
    })
}

pub struct PubkyCriterionSource {
    storage: pubky::PublicStorage,
    max_bytes: u64,
    timeout: Duration,
}

impl PubkyCriterionSource {
    pub fn new(max_bytes: u64, timeout: Duration) -> Result<Self, pubky::Error> {
        Ok(Self {
            storage: pubky::Pubky::new()?.public_storage(),
            max_bytes,
            timeout,
        })
    }

    async fn fetch_document(&self, lock_resource: &str) -> Result<Vec<u8>, LockFetchError> {
        let mut response = self
            .storage
            .get(lock_resource.to_owned())
            .await
            .map_err(|error| match error {
                pubky::Error::Request(RequestError::Server { status, .. })
                    if status.as_u16() == 404 =>
                {
                    LockFetchError::NotFound
                }
                _ => LockFetchError::Unavailable,
            })?;
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| LockFetchError::Unavailable)?
        {
            if (bytes.len() as u64).saturating_add(chunk.len() as u64) > self.max_bytes {
                return Err(LockFetchError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[async_trait]
impl CriterionSource for PubkyCriterionSource {
    async fn criterion(&self, lock_resource: &str) -> Result<LockCriterion, LockFetchError> {
        let document = tokio::time::timeout(self.timeout, self.fetch_document(lock_resource))
            .await
            .map_err(|_| LockFetchError::Unavailable)??;
        parse_criterion(&document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lock(asset: &str, amount: &str) -> String {
        format!(
            r#"{{
              "version": 1,
              "creator": "pubkycreator",
              "primary_resource": {{"path": "content/premium.txt"}},
              "criteria": [{{
                "criterion_id": "criterion-1",
                "verifier_type": "paykit-payment",
                "params": {{"recipient_pubky": "pubkycreator", "amount": "{amount}", "asset": "{asset}"}}
              }}],
              "lock_logic": {{"type": "all", "criteria": ["criterion-1"]}},
              "access_policy": {{"requested_credential_ttl_seconds": 900}},
              "lock_server": {{"override": "pubkylockserver"}},
              "created_at": "2026-08-21T00:00:00Z"
            }}"#
        )
    }

    #[test]
    fn parses_btc_criterion() {
        let criterion = parse_criterion(sample_lock("BTC", "15000").as_bytes()).unwrap();
        assert_eq!(
            criterion,
            LockCriterion {
                asset: "BTC".into(),
                amount: "15000".into(),
                recipient_pubky: "pubkycreator".into()
            }
        );
    }

    #[test]
    fn parses_usd_criterion() {
        let criterion = parse_criterion(sample_lock("USD", "1999").as_bytes()).unwrap();
        assert_eq!(criterion.asset, "USD");
        assert_eq!(criterion.amount, "1999");
    }

    #[test]
    fn rejects_lock_without_paykit_criterion() {
        let doc = r#"{"criteria":[{"verifier_type":"dev-static","params":{}}]}"#;
        assert_eq!(
            parse_criterion(doc.as_bytes()),
            Err(LockFetchError::Invalid)
        );
    }

    #[test]
    fn rejects_non_integer_amount() {
        assert_eq!(
            parse_criterion(sample_lock("USD", "19.99").as_bytes()),
            Err(LockFetchError::Invalid)
        );
        assert_eq!(
            parse_criterion(sample_lock("USD", "").as_bytes()),
            Err(LockFetchError::Invalid)
        );
    }

    #[test]
    fn rejects_missing_fields_and_garbage() {
        assert_eq!(parse_criterion(b"not json"), Err(LockFetchError::Invalid));
        assert_eq!(
            parse_criterion(br#"{"criteria":[]}"#),
            Err(LockFetchError::Invalid)
        );
    }
}
