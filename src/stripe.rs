//! Stripe processor plugin (test mode). Three responsibilities, kept honest:
//!
//! 1. `create_checkout_session` — hosted Checkout, idempotently keyed to the
//!    verification task (`creator‖bundle_id`), so replays mint no duplicates.
//! 2. `retrieve_*` — the API pull. Pulled state is the ONLY thing that
//!    advances a correlation; webhooks merely schedule pulls.
//! 3. `verify_webhook` — constructed-event verification of the
//!    `Stripe-Signature` header (HMAC-SHA256 over `{t}.{raw_body}`).

use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("stripe request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("stripe returned status {status}: {body}")]
    Api { status: u16, body: String },
    #[error("stripe response was not the expected shape: {0}")]
    Shape(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebhookError {
    #[error("webhook signature header is malformed")]
    MalformedHeader,
    #[error("webhook signature does not verify")]
    BadSignature,
    #[error("webhook timestamp outside tolerance")]
    StaleTimestamp,
}

/// The Checkout Session fields the verifier consumes
/// (<https://docs.stripe.com/api/checkout/sessions/object>).
#[derive(Clone, Debug, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    /// Hosted checkout URL; present while the session is open.
    pub url: Option<String>,
    /// `paid` | `unpaid` | `no_payment_required`. THE payment fact —
    /// `status: complete` alone is not payment.
    pub payment_status: Option<String>,
    pub amount_total: Option<i64>,
    pub currency: Option<String>,
    pub expires_at: Option<i64>,
    pub payment_intent: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Charge {
    #[serde(default)]
    pub refunded: bool,
    #[serde(default)]
    pub disputed: bool,
    pub payment_intent: Option<String>,
}

pub struct StripeProcessor {
    http: reqwest::Client,
    api_base: Url,
    secret_key: String,
    pub webhook_secret: Option<String>,
}

impl StripeProcessor {
    pub fn new(api_base: Url, secret_key: String, webhook_secret: Option<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build()
                .expect("static reqwest client configuration"),
            api_base,
            secret_key,
            webhook_secret,
        }
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.api_base.clone();
        url.set_path(path);
        url
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_checkout_session(
        &self,
        reference: &str,
        idempotency_key: &str,
        amount_minor: i64,
        currency_lower: &str,
        product_name: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, StripeError> {
        let amount = amount_minor.to_string();
        let form: Vec<(&str, &str)> = vec![
            ("mode", "payment"),
            ("client_reference_id", reference),
            ("line_items[0][price_data][currency]", currency_lower),
            ("line_items[0][price_data][unit_amount]", &amount),
            (
                "line_items[0][price_data][product_data][name]",
                product_name,
            ),
            ("line_items[0][quantity]", "1"),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
        ];
        let response = self
            .http
            .post(self.endpoint("/v1/checkout/sessions"))
            .bearer_auth(&self.secret_key)
            .header("Idempotency-Key", idempotency_key)
            .form(&form)
            .send()
            .await?;
        Self::parse(response).await
    }

    pub async fn retrieve_session(&self, session_id: &str) -> Result<CheckoutSession, StripeError> {
        let response = self
            .http
            .get(self.endpoint(&format!("/v1/checkout/sessions/{session_id}")))
            .bearer_auth(&self.secret_key)
            .send()
            .await?;
        Self::parse(response).await
    }

    pub async fn retrieve_charge(&self, charge_id: &str) -> Result<Charge, StripeError> {
        let response = self
            .http
            .get(self.endpoint(&format!("/v1/charges/{charge_id}")))
            .bearer_auth(&self.secret_key)
            .send()
            .await?;
        Self::parse(response).await
    }

    async fn parse<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, StripeError> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(StripeError::Api {
                status: status.as_u16(),
                body: body.chars().take(2000).collect(),
            });
        }
        serde_json::from_str(&body).map_err(|error| StripeError::Shape(error.to_string()))
    }

    /// Verifies a `Stripe-Signature` header over the raw payload.
    /// <https://docs.stripe.com/webhooks#verify-manually>
    pub fn verify_webhook(
        webhook_secret: &str,
        signature_header: &str,
        payload: &[u8],
        now_unix: i64,
        tolerance: Duration,
    ) -> Result<(), WebhookError> {
        let mut timestamp: Option<i64> = None;
        let mut candidates: Vec<&str> = Vec::new();
        for part in signature_header.split(',') {
            let mut kv = part.trim().splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("t"), Some(value)) => {
                    timestamp = Some(value.parse().map_err(|_| WebhookError::MalformedHeader)?);
                }
                (Some("v1"), Some(value)) => candidates.push(value),
                _ => {}
            }
        }
        let timestamp = timestamp.ok_or(WebhookError::MalformedHeader)?;
        if candidates.is_empty() {
            return Err(WebhookError::MalformedHeader);
        }
        if (now_unix - timestamp).unsigned_abs() > tolerance.as_secs() {
            return Err(WebhookError::StaleTimestamp);
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())
            .map_err(|_| WebhookError::BadSignature)?;
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let expected = mac.finalize().into_bytes();

        for candidate in candidates {
            if let Ok(bytes) = hex::decode(candidate) {
                // Constant-time comparison via a fresh MAC verify.
                let mut verifier = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())
                    .map_err(|_| WebhookError::BadSignature)?;
                verifier.update(timestamp.to_string().as_bytes());
                verifier.update(b".");
                verifier.update(payload);
                if verifier.verify_slice(&bytes).is_ok() {
                    return Ok(());
                }
            }
        }
        let _ = expected;
        Err(WebhookError::BadSignature)
    }
}

/// Stable idempotency key for a verification task's Nth checkout session.
pub fn idempotency_key(creator: &str, bundle_id: &str, attempt: i32) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(creator.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(bundle_id.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(attempt.to_string().as_bytes());
    format!("fiatv1-{}", hex::encode(hasher.finalize()))
}

/// `client_reference_id` for the session: `creator_bundleid` (both are
/// alphanumeric app-key / Crockford strings, so `_` is an unambiguous joiner).
pub fn client_reference(creator: &str, bundle_id: &str) -> String {
    format!("{creator}_{bundle_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, timestamp: i64, payload: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn accepts_valid_webhook_signature() {
        let payload = br#"{"id":"evt_1","type":"checkout.session.completed"}"#;
        let header = sign("whsec_test", 1_000_000, payload);
        assert!(StripeProcessor::verify_webhook(
            "whsec_test",
            &header,
            payload,
            1_000_010,
            Duration::from_secs(300)
        )
        .is_ok());
    }

    #[test]
    fn rejects_wrong_secret() {
        let payload = b"{}";
        let header = sign("whsec_other", 1_000_000, payload);
        assert_eq!(
            StripeProcessor::verify_webhook(
                "whsec_test",
                &header,
                payload,
                1_000_010,
                Duration::from_secs(300)
            ),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let header = sign("whsec_test", 1_000_000, b"{\"a\":1}");
        assert_eq!(
            StripeProcessor::verify_webhook(
                "whsec_test",
                &header,
                b"{\"a\":2}",
                1_000_010,
                Duration::from_secs(300)
            ),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn rejects_stale_timestamp() {
        let payload = b"{}";
        let header = sign("whsec_test", 1_000_000, payload);
        assert_eq!(
            StripeProcessor::verify_webhook(
                "whsec_test",
                &header,
                payload,
                1_000_000 + 301,
                Duration::from_secs(300)
            ),
            Err(WebhookError::StaleTimestamp)
        );
    }

    #[test]
    fn rejects_header_without_v1() {
        assert_eq!(
            StripeProcessor::verify_webhook(
                "whsec_test",
                "t=1000000",
                b"{}",
                1_000_000,
                Duration::from_secs(300)
            ),
            Err(WebhookError::MalformedHeader)
        );
    }

    #[test]
    fn idempotency_key_is_stable_per_attempt() {
        let a = idempotency_key("pubkyabc", "BUNDLE", 1);
        let b = idempotency_key("pubkyabc", "BUNDLE", 1);
        let c = idempotency_key("pubkyabc", "BUNDLE", 2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
