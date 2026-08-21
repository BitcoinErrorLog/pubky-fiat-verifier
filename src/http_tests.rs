//! Handler-level tests: the full router against an in-memory store, a mock
//! Stripe API, and a mock Paykit Server. Signatures are real ed25519 over
//! canonical JSON — exactly what the Lock Server sends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use time::OffsetDateTime;
use tokio::net::TcpListener;

use crate::http::{router, AppState};
use crate::lock_fetch::{CriterionSource, LockCriterion, LockFetchError};
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::store::memory::MemoryStore;
use crate::store::{CorrelationState, CorrelationStore};
use crate::stripe::StripeProcessor;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const READER: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const WEBHOOK_SECRET: &str = "whsec_unit_test";

fn locks_key() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32])
}

fn sign(key: &SigningKey, body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes())
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

struct StaticCriteria(Mutex<std::collections::HashMap<String, LockCriterion>>);

#[async_trait]
impl CriterionSource for StaticCriteria {
    async fn criterion(&self, lock_resource: &str) -> Result<LockCriterion, LockFetchError> {
        self.0
            .lock()
            .unwrap()
            .get(lock_resource)
            .cloned()
            .ok_or(LockFetchError::NotFound)
    }
}

// -- mock Stripe -------------------------------------------------------------

#[derive(Clone, Default)]
struct MockStripe {
    /// (idempotency_key, form_body) per create call.
    creates: Arc<Mutex<Vec<(String, String)>>>,
    /// session id -> session object returned by retrieve.
    sessions: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    charges: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    counter: Arc<Mutex<u32>>,
}

impl MockStripe {
    fn set_payment_status(&self, session_id: &str, payment_status: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(session_id).unwrap();
        session["payment_status"] = json!(payment_status);
        if payment_status == "paid" {
            session["status"] = json!("complete");
            session["payment_intent"] = json!(format!("pi_{session_id}"));
        }
    }
}

async fn mock_create_session(
    State(mock): State<MockStripe>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let idempotency = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let form = String::from_utf8(body.to_vec()).unwrap();
    {
        let creates = mock.creates.lock().unwrap();
        // Stripe idempotency: same key returns the same session.
        for (index, (key, _)) in creates.iter().enumerate() {
            if *key == idempotency {
                let id = format!("cs_test_{}", index + 1);
                let session = mock.sessions.lock().unwrap().get(&id).cloned().unwrap();
                return Json(session);
            }
        }
    }
    let mut counter = mock.counter.lock().unwrap();
    *counter += 1;
    let id = format!("cs_test_{}", *counter);
    let amount: i64 = form
        .split('&')
        .find_map(|pair| pair.strip_prefix("line_items%5B0%5D%5Bprice_data%5D%5Bunit_amount%5D="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let session = json!({
        "id": id,
        "object": "checkout.session",
        "url": format!("https://checkout.stripe.test/c/pay/{id}"),
        "status": "open",
        "payment_status": "unpaid",
        "amount_total": amount,
        "currency": "usd",
        "expires_at": OffsetDateTime::now_utc().unix_timestamp() + 86_400,
        "client_reference_id": format!("{CREATOR}_{BUNDLE}"),
        "livemode": false
    });
    mock.sessions
        .lock()
        .unwrap()
        .insert(id.clone(), session.clone());
    mock.creates.lock().unwrap().push((idempotency, form));
    Json(session)
}

async fn mock_get_session(
    State(mock): State<MockStripe>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.sessions.lock().unwrap().get(&id) {
        Some(session) => Json(session.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response(),
    }
}

async fn mock_get_charge(
    State(mock): State<MockStripe>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.charges.lock().unwrap().get(&id) {
        Some(charge) => Json(charge.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response(),
    }
}

// -- mock Paykit Server -------------------------------------------------------

/// (path, forwarded signature header, forwarded raw body)
type CapturedForward = (String, Option<String>, Vec<u8>);

#[derive(Clone, Default)]
struct MockPaykit {
    requests: Arc<Mutex<Vec<CapturedForward>>>,
}

async fn mock_paykit_invoices(
    State(mock): State<MockPaykit>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.requests.lock().unwrap().push((
        "/invoices".into(),
        headers
            .get("x-paykit-signature")
            .map(|value| value.to_str().unwrap().to_owned()),
        body.to_vec(),
    ));
    axum::http::StatusCode::NO_CONTENT
}

async fn mock_paykit_status(
    State(mock): State<MockPaykit>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.requests.lock().unwrap().push((
        "/transactions/status".into(),
        headers
            .get("x-paykit-signature")
            .map(|value| value.to_str().unwrap().to_owned()),
        body.to_vec(),
    ));
    Json(json!({"status": "detected", "confirmations": 0, "amount_matched": true}))
}

// -- harness -------------------------------------------------------------------

struct Harness {
    base: String,
    store: Arc<dyn CorrelationStore>,
    stripe_mock: MockStripe,
    paykit_mock: MockPaykit,
    http: reqwest::Client,
    settlement_delay: Duration,
}

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn harness_with_delay(settlement_delay: Duration) -> Harness {
    let stripe_mock = MockStripe::default();
    let stripe_url = spawn(
        Router::new()
            .route("/v1/checkout/sessions", post(mock_create_session))
            .route("/v1/checkout/sessions/{id}", get(mock_get_session))
            .route("/v1/charges/{id}", get(mock_get_charge))
            .with_state(stripe_mock.clone()),
    )
    .await;

    let paykit_mock = MockPaykit::default();
    let paykit_url = spawn(
        Router::new()
            .route("/invoices", post(mock_paykit_invoices))
            .route("/transactions/status", post(mock_paykit_status))
            .with_state(paykit_mock.clone()),
    )
    .await;

    let mut criteria = std::collections::HashMap::new();
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/usd.json"),
        LockCriterion {
            asset: "USD".into(),
            amount: "1999".into(),
            recipient_pubky: CREATOR.into(),
        },
    );
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/btc.json"),
        LockCriterion {
            asset: "BTC".into(),
            amount: "15000".into(),
            recipient_pubky: CREATOR.into(),
        },
    );
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/eur.json"),
        LockCriterion {
            asset: "EUR".into(),
            amount: "500".into(),
            recipient_pubky: CREATOR.into(),
        },
    );

    let store: Arc<dyn CorrelationStore> = Arc::new(MemoryStore::default());
    let state = Arc::new(AppState {
        trusted_key: locks_key().verifying_key(),
        store: store.clone(),
        stripe: Some(Arc::new(StripeProcessor::new(
            url::Url::parse(&stripe_url).unwrap(),
            "sk_test_unit".into(),
            Some(WEBHOOK_SECRET.into()),
        ))),
        criterion_source: Arc::new(StaticCriteria(Mutex::new(criteria))),
        proxy: Arc::new(PaykitProxy::new(url::Url::parse(&paykit_url).unwrap())),
        settlement_delay,
        synthesized_confirmations: 1,
        allowed_assets: vec!["USD".into()],
        checkout_success_url: "https://app.test/success".into(),
        checkout_cancel_url: "https://app.test/cancel".into(),
        checkout_limiter: TokenBucket::new(100, 100),
    });
    let base = spawn(router(state)).await;
    Harness {
        base,
        store,
        stripe_mock,
        paykit_mock,
        http: reqwest::Client::new(),
        settlement_delay,
    }
}

async fn harness() -> Harness {
    harness_with_delay(Duration::from_secs(300)).await
}

impl Harness {
    async fn signed_post(&self, path: &str, body: &[u8]) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .header("x-paykit-signature", sign(&locks_key(), body))
            .body(body.to_vec())
            .send()
            .await
            .unwrap()
    }

    async fn invoice(&self, lock: &str, bundle: &str) -> reqwest::Response {
        let body = canonical(&json!({
            "bundle_id": bundle,
            "lock_resource": format!("{CREATOR}/pub/locks.app/{lock}.json"),
            "reader": READER,
        }));
        self.signed_post("/invoices", &body).await
    }

    async fn status(&self, bundle: &str) -> Value {
        let body = canonical(&json!({"bundle_id": bundle, "creator": CREATOR}));
        self.signed_post("/transactions/status", &body)
            .await
            .json()
            .await
            .unwrap()
    }

    fn webhook_signature(&self, timestamp: i64, payload: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    async fn send_webhook(&self, event: &Value) -> reqwest::Response {
        let payload = serde_json::to_vec(event).unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.http
            .post(format!("{}/webhooks/stripe", self.base))
            .header("stripe-signature", self.webhook_signature(now, &payload))
            .body(payload)
            .send()
            .await
            .unwrap()
    }
}

// -- tests ----------------------------------------------------------------------

#[tokio::test]
async fn btc_invoice_is_proxied_verbatim_with_original_signature() {
    let harness = harness().await;
    let body = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/btc.json"),
        "reader": READER,
    }));
    let signature = sign(&locks_key(), &body);
    let response = harness.signed_post("/invoices", &body).await;
    assert_eq!(response.status().as_u16(), 204);

    let requests = harness.paykit_mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let (path, forwarded_signature, forwarded_body) = &requests[0];
    assert_eq!(path, "/invoices");
    assert_eq!(forwarded_signature.as_deref(), Some(signature.as_str()));
    assert_eq!(forwarded_body, &body);
}

#[tokio::test]
async fn unknown_status_is_proxied_to_paykit() {
    let harness = harness().await;
    let status = harness.status("UNKNOWNBUNDLE1").await;
    assert_eq!(status["status"], "detected");
    let requests = harness.paykit_mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "/transactions/status");
}

#[tokio::test]
async fn unsigned_and_garbage_signed_requests_are_rejected() {
    let harness = harness().await;
    let body = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/usd.json"),
        "reader": READER,
    }));
    let unsigned = harness
        .http
        .post(format!("{}/invoices", harness.base))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);

    let garbage = harness
        .http
        .post(format!("{}/invoices", harness.base))
        .header("x-paykit-signature", URL_SAFE_NO_PAD.encode([0_u8; 64]))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(garbage.status().as_u16(), 401);
    assert!(harness.paykit_mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn usd_invoice_creates_idempotent_checkout_session() {
    let harness = harness().await;
    let first = harness.invoice("usd", BUNDLE).await;
    assert_eq!(first.status().as_u16(), 204);

    // Exact replay: same identity, same terms -> 204, no second session.
    let replay = harness.invoice("usd", BUNDLE).await;
    assert_eq!(replay.status().as_u16(), 204);
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 1);

    let (idempotency_key, form) = harness.stripe_mock.creates.lock().unwrap()[0].clone();
    assert!(idempotency_key.starts_with("fiatv1-"));
    assert!(form.contains("mode=payment"));
    assert!(form.contains("unit_amount%5D=1999"));
    assert!(form.contains("currency%5D=usd"));

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    assert_eq!(row.session_id.as_deref(), Some("cs_test_1"));
    assert_eq!(row.amount_minor, 1999);
    // Nothing was proxied to the Paykit Server on the fiat path.
    assert!(harness.paykit_mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn same_bundle_with_different_terms_conflicts() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    // Same (creator, bundle_id) bound to a different reader -> 409, mirroring
    // paykit-server's invoice-binding conflict semantics.
    let conflicting = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/usd.json"),
        "reader": CREATOR,
    }));
    let response = harness.signed_post("/invoices", &conflicting).await;
    assert_eq!(response.status().as_u16(), 409);
}

#[tokio::test]
async fn disallowed_fiat_asset_fails_the_submission() {
    let harness = harness().await;
    let response = harness.invoice("eur", BUNDLE).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn fiat_status_reports_undetected_until_the_pull_says_paid() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "undetected", "confirmations": 0, "amount_matched": false})
    );
}

#[tokio::test]
async fn webhook_hint_is_overruled_by_unpaid_pull() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // A webhook claims completion, but the API still says unpaid.
    // The pull wins: nothing moves.
    let event = json!({
        "id": "evt_lying_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}"),
            "payment_status": "paid"
        }}
    });
    let response = harness.send_webhook(&event).await;
    assert_eq!(response.status().as_u16(), 200);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "undetected");
}

#[tokio::test]
async fn paid_pull_detects_then_settlement_delay_confirms() {
    let harness = harness_with_delay(Duration::from_secs(2)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Payment happens at the processor; webhook arrives; the pull verifies.
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let event = json!({
        "id": "evt_real_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}")
        }}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);

    // Inside the settlement delay: detected, never confirmed.
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": true})
    );

    // After the delay: the status call re-pulls and promotes.
    tokio::time::sleep(harness.settlement_delay + Duration::from_millis(200)).await;
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "confirmed", "confirmations": 1, "amount_matched": true})
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Confirmed);
}

#[tokio::test]
async fn duplicate_webhook_events_are_deduplicated() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let event = json!({
        "id": "evt_dup",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}")}}
    });
    let first: Value = harness.send_webhook(&event).await.json().await.unwrap();
    assert_eq!(first, json!({"received": true}));
    let second: Value = harness.send_webhook(&event).await.json().await.unwrap();
    assert_eq!(second, json!({"received": true, "duplicate": true}));
}

#[tokio::test]
async fn webhook_with_bad_signature_is_rejected() {
    let harness = harness().await;
    let payload = serde_json::to_vec(&json!({"id": "evt_x", "type": "t"})).unwrap();
    let response = harness
        .http
        .post(format!("{}/webhooks/stripe", harness.base))
        .header("stripe-signature", "t=1,v1=deadbeef")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn detection_works_without_webhooks_via_status_poll() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    // No webhook at all: the Lock Server's own status poll triggers the pull.
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], true);
}

#[tokio::test]
async fn amount_mismatch_is_reported_and_never_promotes() {
    let harness = harness_with_delay(Duration::from_secs(0)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    {
        let mut sessions = harness.stripe_mock.sessions.lock().unwrap();
        let session = sessions.get_mut("cs_test_1").unwrap();
        session["payment_status"] = json!("paid");
        session["amount_total"] = json!(1); // paid the wrong amount
    }
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": false})
    );
    // Even with a zero delay it must not confirm.
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], false);
}

#[tokio::test]
async fn checkout_sessions_returns_url_and_reminting_only_after_expiry() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let fetch = || async {
        harness
            .http
            .post(format!("{}/checkout-sessions", harness.base))
            .json(&json!({"creator": CREATOR, "bundle_id": BUNDLE}))
            .send()
            .await
            .unwrap()
    };
    let first: Value = fetch().await.json().await.unwrap();
    assert_eq!(
        first["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_1"
    );
    assert_eq!(first["processor"], "stripe");

    // Same live session on repeat.
    let repeat: Value = fetch().await.json().await.unwrap();
    assert_eq!(repeat["checkout_url"], first["checkout_url"]);
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 1);

    // Force expiry -> replacement is minted with a new idempotency key.
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "cs_test_1",
            first["checkout_url"].as_str().unwrap(),
            1,
            1,
        )
        .await
        .unwrap();
    let reminted: Value = fetch().await.json().await.unwrap();
    assert_eq!(
        reminted["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_2"
    );
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn checkout_sessions_unknown_bundle_is_404_and_paid_conflicts() {
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    let unknown = harness
        .http
        .post(format!("{}/checkout-sessions", harness.base))
        .json(&json!({"creator": CREATOR, "bundle_id": "NOPE1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status().as_u16(), 404);

    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let _ = harness.status(BUNDLE).await; // detection pull
    let paid = harness
        .http
        .post(format!("{}/checkout-sessions", harness.base))
        .json(&json!({"creator": CREATOR, "bundle_id": BUNDLE}))
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status().as_u16(), 409);
}

#[tokio::test]
async fn verified_reversal_blocks_promotion() {
    let harness = harness_with_delay(Duration::from_secs(0)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let status = harness.status(BUNDLE).await; // detect + record payment_intent
                                               // Zero delay: this status call would normally promote on its next poll.
    assert!(status["status"] == "confirmed" || status["status"] == "detected");

    // Reset to a paid-but-not-yet-confirmed shape for the reversal test.
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let _ = harness.status(BUNDLE).await; // detected; payment_intent = pi_cs_test_1
    harness.stripe_mock.charges.lock().unwrap().insert(
        "ch_reversed".into(),
        json!({"id": "ch_reversed", "refunded": true, "disputed": false,
               "payment_intent": "pi_cs_test_1"}),
    );
    let event = json!({
        "id": "evt_reversal",
        "type": "charge.refunded",
        "data": {"object": {"id": "ch_reversed"}}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Reversed);
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "undetected");
}

#[tokio::test]
async fn health_reports_ok() {
    let harness = harness().await;
    let health: Value = harness
        .http
        .get(format!("{}/health", harness.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["stripe_enabled"], true);
}
