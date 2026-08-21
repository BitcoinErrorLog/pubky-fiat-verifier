//! HTTP surface.
//!
//! Impersonated Paykit wire contract (Lock Server–facing, signed):
//!   POST /invoices              — dispatch by criterion asset
//!   POST /transactions/status   — BTC forwarded, fiat answered locally
//!
//! Gateway-native surface:
//!   POST /checkout-sessions     — buyer fetches the hosted checkout URL
//!   POST /webhooks/stripe       — processor hints (verified, deduped, then
//!                                 superseded by an API pull)
//!   GET  /health

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::auth::{parse_canonical_strict, verify_signature, SIGNATURE_HEADER};
use crate::error::ApiError;
use crate::lock_fetch::{CriterionSource, LockFetchError};
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::state::{report, Report};
use crate::store::{CorrelationState, CorrelationStore, InsertOutcome, NewCorrelation};
use crate::stripe::{client_reference, idempotency_key, StripeProcessor};
use crate::verification::{promote_if_still_paid, pull_and_apply};
use crate::wire::{
    parse_lock_resource, validate_id, CheckoutSessionRequest, CheckoutSessionResponse,
    InvoiceRequest, StatusRequest,
};

const MAX_BODY_BYTES: usize = 65_536;
const WEBHOOK_TOLERANCE: Duration = Duration::from_secs(300);
/// A checkout session this close to expiry is replaced rather than returned.
const SESSION_EXPIRY_SLACK_SECONDS: i64 = 60;

pub struct AppState {
    pub trusted_key: VerifyingKey,
    pub store: Arc<dyn CorrelationStore>,
    pub stripe: Option<Arc<StripeProcessor>>,
    pub criterion_source: Arc<dyn CriterionSource>,
    pub proxy: Arc<PaykitProxy>,
    pub settlement_delay: Duration,
    pub synthesized_confirmations: u32,
    pub allowed_assets: Vec<String>,
    pub checkout_success_url: String,
    pub checkout_cancel_url: String,
    pub checkout_limiter: TokenBucket,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/invoices", post(create_invoice))
        .route("/transactions/status", post(transaction_status))
        .route("/checkout-sessions", post(checkout_session))
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn signature_string(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or(ApiError::InvalidSignature)
}

async fn create_invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    if let Err(error) = verify_signature(&state.trusted_key, &headers, &raw_body) {
        return error.into_response();
    }
    let request: InvoiceRequest = match parse_canonical_strict(&raw_body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if validate_id(&request.bundle_id).is_err() || request.reader.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }
    let (creator, _path) = match parse_lock_resource(&request.lock_resource) {
        Ok(parts) => parts,
        Err(error) => return error.into_response(),
    };

    let criterion = match state
        .criterion_source
        .criterion(&request.lock_resource)
        .await
    {
        Ok(criterion) => criterion,
        Err(LockFetchError::NotFound) => return ApiError::LockNotFound.into_response(),
        Err(LockFetchError::Unavailable) => return ApiError::Unavailable.into_response(),
        Err(LockFetchError::Invalid) => return ApiError::InvalidRequest.into_response(),
    };

    if criterion.asset == "BTC" {
        tracing::info!(
            bundle_id = %request.bundle_id,
            lock_resource = %request.lock_resource,
            "dispatch: BTC criterion, proxying invoice to paykit-server"
        );
        let signature = match signature_string(&headers) {
            Ok(signature) => signature,
            Err(error) => return error.into_response(),
        };
        return state.proxy.forward("invoices", &signature, raw_body).await;
    }

    // Fiat path.
    if !state
        .allowed_assets
        .iter()
        .any(|asset| asset == &criterion.asset)
    {
        tracing::warn!(
            asset = %criterion.asset,
            bundle_id = %request.bundle_id,
            "criterion asset is not enabled on this gateway"
        );
        return ApiError::InvalidRequest.into_response();
    }
    // v1 policy: the payment recipient is the lock creator. Locks enforces
    // this at lock creation; re-checked here as processor-drift defense.
    if criterion.recipient_pubky != creator {
        return ApiError::InvalidRequest.into_response();
    }
    let amount_minor: i64 = match criterion.amount.parse::<i64>() {
        Ok(amount) if amount > 0 => amount,
        _ => return ApiError::InvalidRequest.into_response(),
    };
    let Some(stripe) = state.stripe.as_ref() else {
        tracing::error!(
            bundle_id = %request.bundle_id,
            "fiat invoice refused: no Stripe processor configured (fail-closed)"
        );
        return ApiError::Unavailable.into_response();
    };

    let outcome = match state
        .store
        .insert_new(NewCorrelation {
            creator: creator.to_owned(),
            bundle_id: request.bundle_id.clone(),
            lock_resource: request.lock_resource.clone(),
            reader: request.reader.clone(),
            asset: criterion.asset.clone(),
            amount_minor,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%error, "correlation insert failed");
            return ApiError::Unavailable.into_response();
        }
    };

    match outcome {
        InsertOutcome::Conflict => {
            tracing::warn!(
                creator,
                bundle_id = %request.bundle_id,
                "invoice conflict: identity already bound to different terms"
            );
            ApiError::InvoiceConflict.into_response()
        }
        InsertOutcome::ExactReplay => {
            let existing = match state.store.get(creator, &request.bundle_id).await {
                Ok(Some(existing)) => existing,
                _ => return ApiError::Unavailable.into_response(),
            };
            if existing.session_id.is_some() {
                return StatusCode::NO_CONTENT.into_response();
            }
            // Earlier attempt persisted the row but died before the session
            // existed: idempotently create it now.
            match mint_session(
                &state,
                stripe,
                creator,
                &request.bundle_id,
                &criterion.asset,
                amount_minor,
                existing.session_attempt + 1,
            )
            .await
            {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(response) => response,
            }
        }
        InsertOutcome::Inserted => {
            match mint_session(
                &state,
                stripe,
                creator,
                &request.bundle_id,
                &criterion.asset,
                amount_minor,
                1,
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        creator,
                        bundle_id = %request.bundle_id,
                        asset = %criterion.asset,
                        amount_minor,
                        "fiat invoice created with checkout session"
                    );
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(response) => response,
            }
        }
    }
}

async fn mint_session(
    state: &Arc<AppState>,
    stripe: &Arc<StripeProcessor>,
    creator: &str,
    bundle_id: &str,
    asset: &str,
    amount_minor: i64,
    attempt: i32,
) -> Result<CheckoutSessionResponse, Response> {
    let session = stripe
        .create_checkout_session(
            &client_reference(creator, bundle_id),
            &idempotency_key(creator, bundle_id, attempt),
            amount_minor,
            &asset.to_ascii_lowercase(),
            "Marketplace listing (Locks entitlement)",
            &state.checkout_success_url,
            &state.checkout_cancel_url,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, creator, bundle_id, "stripe checkout session creation failed");
            ApiError::Unavailable.into_response()
        })?;
    let checkout_url = session.url.clone().ok_or_else(|| {
        tracing::error!(session_id = %session.id, "created checkout session has no url");
        ApiError::Unavailable.into_response()
    })?;
    let expires_at = session.expires_at.unwrap_or(0);
    state
        .store
        .set_session(
            creator,
            bundle_id,
            &session.id,
            &checkout_url,
            expires_at,
            attempt,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to persist checkout session");
            ApiError::Unavailable.into_response()
        })?;
    Ok(CheckoutSessionResponse {
        checkout_url,
        processor: "stripe",
        expires_at,
    })
}

async fn transaction_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    if let Err(error) = verify_signature(&state.trusted_key, &headers, &raw_body) {
        return error.into_response();
    }
    let request: StatusRequest = match parse_canonical_strict(&raw_body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if validate_id(&request.bundle_id).is_err() || request.creator.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }

    let correlation = match state.store.get(&request.creator, &request.bundle_id).await {
        Ok(correlation) => correlation,
        Err(error) => {
            tracing::error!(%error, "correlation lookup failed");
            return ApiError::Unavailable.into_response();
        }
    };

    let correlation = match correlation {
        // Unknown here => not a fiat correlation this gateway minted. All
        // BTC invoices (including every pre-cutover one) live in the real
        // Paykit Server, so forward and mirror its answer (404 included —
        // upstream treats it as retryable VerificationPending).
        None => {
            let signature = match signature_string(&headers) {
                Ok(signature) => signature,
                Err(error) => return error.into_response(),
            };
            return state
                .proxy
                .forward("transactions/status", &signature, raw_body)
                .await;
        }
        Some(correlation) if correlation.asset == "BTC" => {
            let signature = match signature_string(&headers) {
                Ok(signature) => signature,
                Err(error) => return error.into_response(),
            };
            return state
                .proxy
                .forward("transactions/status", &signature, raw_body)
                .await;
        }
        Some(correlation) => correlation,
    };

    let now = OffsetDateTime::now_utc();

    // Opportunistic pull while awaiting payment: the Lock Server polls this
    // endpoint ~every 30s, which doubles as the payment observation loop, so
    // fiat detection does not depend on webhook delivery at all.
    let correlation =
        if correlation.state == CorrelationState::Created && correlation.session_id.is_some() {
            if let Some(stripe) = state.stripe.as_ref() {
                pull_and_apply(&state.store, stripe, &correlation, now).await;
                match state.store.get(&request.creator, &request.bundle_id).await {
                    Ok(Some(refreshed)) => refreshed,
                    _ => correlation,
                }
            } else {
                correlation
            }
        } else {
            correlation
        };

    let status = match report(
        &correlation,
        now,
        state.settlement_delay,
        state.synthesized_confirmations,
    ) {
        Report::Immediate(status) => status,
        Report::PromotionDue { fallback } => match state.stripe.as_ref() {
            Some(stripe) => {
                if promote_if_still_paid(&state.store, stripe, &correlation, now).await {
                    crate::wire::TransactionStatus {
                        status: crate::wire::StatusKind::Confirmed,
                        confirmations: state.synthesized_confirmations,
                        amount_matched: true,
                    }
                } else {
                    fallback
                }
            }
            None => fallback,
        },
    };
    Json(status).into_response()
}

async fn checkout_session(
    State(state): State<Arc<AppState>>,
    body: Result<Json<CheckoutSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !state.checkout_limiter.try_take() {
        return ApiError::RateLimited.into_response();
    }
    let Ok(Json(request)) = body else {
        return ApiError::InvalidRequest.into_response();
    };
    if validate_id(&request.bundle_id).is_err() || request.creator.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }
    let Some(stripe) = state.stripe.as_ref() else {
        return ApiError::Unavailable.into_response();
    };
    let correlation = match state.store.get(&request.creator, &request.bundle_id).await {
        Ok(Some(correlation)) if correlation.asset != "BTC" => correlation,
        Ok(_) => return ApiError::NotFound.into_response(),
        Err(error) => {
            tracing::error!(%error, "correlation lookup failed");
            return ApiError::Unavailable.into_response();
        }
    };
    if correlation.state != CorrelationState::Created {
        // Paid/confirmed: nothing left to check out. Reversed: this bundle's
        // payment was reversed; the task will expire — a fresh purchase needs
        // a fresh proof bundle.
        return ApiError::InvoiceConflict.into_response();
    }
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if let (Some(url), Some(expires_at)) = (
        correlation.checkout_url.clone(),
        correlation.checkout_expires_at,
    ) {
        if expires_at > now_unix + SESSION_EXPIRY_SLACK_SECONDS {
            return Json(CheckoutSessionResponse {
                checkout_url: url,
                processor: "stripe",
                expires_at,
            })
            .into_response();
        }
    }
    // Session expired (or was never fully persisted): mint a replacement.
    match mint_session(
        &state,
        stripe,
        &request.creator,
        &request.bundle_id,
        &correlation.asset,
        correlation.amount_minor,
        correlation.session_attempt + 1,
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(response) => response,
    }
}

async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let Some(stripe) = state.stripe.as_ref() else {
        return ApiError::Unavailable.into_response();
    };
    let Some(webhook_secret) = stripe.webhook_secret.as_deref() else {
        tracing::warn!("webhook received but STRIPE_WEBHOOK_SECRET is not configured");
        return ApiError::Unavailable.into_response();
    };
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return ApiError::InvalidSignature.into_response();
    };
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(error) = StripeProcessor::verify_webhook(
        webhook_secret,
        signature,
        &raw_body,
        now_unix,
        WEBHOOK_TOLERANCE,
    ) {
        tracing::warn!(%error, "stripe webhook signature rejected");
        return ApiError::InvalidSignature.into_response();
    }

    let event: Value = match serde_json::from_slice(&raw_body) {
        Ok(event) => event,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let (Some(event_id), Some(event_type)) = (
        event.get("id").and_then(Value::as_str),
        event.get("type").and_then(Value::as_str),
    ) else {
        return ApiError::InvalidRequest.into_response();
    };
    match state.store.record_webhook_event(event_id, event_type).await {
        Ok(true) => {}
        Ok(false) => return Json(json!({"received": true, "duplicate": true})).into_response(),
        Err(error) => {
            tracing::error!(%error, "webhook dedupe persistence failed");
            return ApiError::Unavailable.into_response();
        }
    }
    let object = event
        .pointer("/data/object")
        .cloned()
        .unwrap_or(Value::Null);
    tracing::info!(event_id, event_type, "stripe webhook accepted (hint only)");

    let now = OffsetDateTime::now_utc();
    match event_type {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            let Some(reference) = object.get("client_reference_id").and_then(Value::as_str) else {
                tracing::warn!(event_id, "completed session carries no client_reference_id");
                return Json(json!({"received": true})).into_response();
            };
            let Some((creator, bundle_id)) = reference.split_once('_') else {
                tracing::warn!(event_id, reference, "unparseable client_reference_id");
                return Json(json!({"received": true})).into_response();
            };
            match state.store.get(creator, bundle_id).await {
                Ok(Some(correlation)) => {
                    // The webhook body is a hint. The pull is the fact.
                    pull_and_apply(&state.store, stripe, &correlation, now).await;
                }
                Ok(None) => {
                    tracing::warn!(event_id, reference, "webhook for unknown correlation");
                }
                Err(error) => tracing::error!(%error, "correlation lookup failed"),
            }
        }
        "charge.refunded" | "charge.dispute.created" => {
            if let Some(charge_id) = object.get("id").and_then(Value::as_str) {
                // Verify the reversal by pulling the charge before acting.
                match stripe.retrieve_charge(charge_id).await {
                    Ok(charge) if charge.refunded || charge.disputed => {
                        if let Some(payment_intent) = charge.payment_intent.as_deref() {
                            match state.store.find_by_payment_intent(payment_intent).await {
                                Ok(Some(correlation)) => {
                                    if let Err(error) = state
                                        .store
                                        .mark_reversed(&correlation.creator, &correlation.bundle_id)
                                        .await
                                    {
                                        tracing::error!(%error, "failed to persist reversal");
                                    } else {
                                        tracing::warn!(
                                            creator = %correlation.creator,
                                            bundle_id = %correlation.bundle_id,
                                            charge_id,
                                            "verified reversal recorded; promotion suppressed"
                                        );
                                    }
                                }
                                Ok(None) => tracing::warn!(
                                    charge_id,
                                    "reversal for a charge with no open correlation"
                                ),
                                Err(error) => tracing::error!(%error, "lookup failed"),
                            }
                        }
                    }
                    Ok(_) => tracing::warn!(
                        charge_id,
                        "reversal webhook not corroborated by charge pull; ignored"
                    ),
                    Err(error) => tracing::error!(%error, charge_id, "charge pull failed"),
                }
            }
        }
        other => {
            tracing::debug!(event_type = other, "ignoring unhandled webhook event type");
        }
    }
    Json(json!({"received": true})).into_response()
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let db_healthy = state.store.healthy().await;
    let body = json!({
        "status": if db_healthy { "ok" } else { "degraded" },
        "database": db_healthy,
        "stripe_enabled": state.stripe.is_some(),
        "stripe_webhook_configured": state
            .stripe
            .as_ref()
            .is_some_and(|stripe| stripe.webhook_secret.is_some()),
        "version": env!("CARGO_PKG_VERSION"),
    });
    let status = if db_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
