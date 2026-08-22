//! The pull-is-truth core: every state advance flows through a fresh read of
//! the processor's API. Webhooks and the slow poll both funnel into
//! `pull_and_apply`; the promotion to `confirmed` additionally requires the
//! settlement delay to have elapsed AND a fresh pull at promotion time.
//!
//! Both processor plugins answer the same question — "does your read API say
//! this correlation's session/order is paid, for exactly the criterion's
//! amount?" — and dispatch happens on the processor the correlation was
//! bound to when its session was minted.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::paypal::{decimal_to_minor, PaypalProcessor};
use crate::store::{Correlation, CorrelationState, CorrelationStore};
use crate::stripe::StripeProcessor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessorKind {
    Stripe,
    Paypal,
}

impl ProcessorKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stripe" => Some(Self::Stripe),
            "paypal" => Some(Self::Paypal),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::Paypal => "paypal",
        }
    }
}

/// The configured processor plugins. Either may be absent (fail-closed 503
/// on its path); with neither configured the whole fiat path is disabled.
pub struct Processors {
    pub stripe: Option<Arc<StripeProcessor>>,
    pub paypal: Option<Arc<PaypalProcessor>>,
}

impl Processors {
    pub fn any_configured(&self) -> bool {
        self.stripe.is_some() || self.paypal.is_some()
    }

    pub fn is_configured(&self, kind: ProcessorKind) -> bool {
        match kind {
            ProcessorKind::Stripe => self.stripe.is_some(),
            ProcessorKind::Paypal => self.paypal.is_some(),
        }
    }

    /// The single configured processor, when exactly one is configured.
    /// Invoice-time minting is eager only in that case; with both configured
    /// the mint waits for the buyer's checkout request (which carries the
    /// processor choice).
    pub fn sole_configured(&self) -> Option<ProcessorKind> {
        match (&self.stripe, &self.paypal) {
            (Some(_), None) => Some(ProcessorKind::Stripe),
            (None, Some(_)) => Some(ProcessorKind::Paypal),
            _ => None,
        }
    }
}

/// The processor a correlation is bound to. Rows minted before the
/// `processor` column existed are Stripe rows (Stripe was the only
/// processor then); rows without a session are not bound yet.
pub fn bound_processor(correlation: &Correlation) -> Option<ProcessorKind> {
    match correlation.processor.as_deref() {
        Some(value) => ProcessorKind::parse(value),
        None => correlation
            .session_id
            .as_ref()
            .map(|_| ProcessorKind::Stripe),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullOutcome {
    /// The processor's read API says paid; carries the amount check.
    Paid {
        amount_matched: bool,
    },
    Unpaid,
    /// Transport or processor error: state must not move.
    Unavailable,
}

/// Pulls the correlation's session/order from its bound processor and
/// applies the verified fact to the store. Returns what the pull established.
pub async fn pull_and_apply(
    store: &Arc<dyn CorrelationStore>,
    processors: &Processors,
    correlation: &Correlation,
    now: OffsetDateTime,
) -> PullOutcome {
    let Some(kind) = bound_processor(correlation) else {
        return PullOutcome::Unpaid;
    };
    let pulled = match kind {
        ProcessorKind::Stripe => match processors.stripe.as_ref() {
            Some(stripe) => pull_stripe(stripe, correlation).await,
            None => return PullOutcome::Unavailable,
        },
        ProcessorKind::Paypal => match processors.paypal.as_ref() {
            Some(paypal) => pull_paypal(paypal, correlation).await,
            None => return PullOutcome::Unavailable,
        },
    };
    let (amount_matched, payment_reference) = match pulled {
        Pulled::Paid {
            amount_matched,
            payment_reference,
        } => (amount_matched, payment_reference),
        Pulled::Unpaid => return PullOutcome::Unpaid,
        Pulled::Unavailable => return PullOutcome::Unavailable,
    };
    if !amount_matched {
        tracing::error!(
            creator = %correlation.creator,
            bundle_id = %correlation.bundle_id,
            processor = kind.as_str(),
            expected_amount = correlation.amount_minor,
            expected_asset = %correlation.asset,
            "paid checkout does not match the lock criterion"
        );
    }
    if correlation.state == CorrelationState::Created {
        if let Err(error) = store
            .mark_paid(
                &correlation.creator,
                &correlation.bundle_id,
                amount_matched,
                payment_reference.as_deref(),
                now,
            )
            .await
        {
            tracing::error!(%error, "failed to persist paid observation");
            return PullOutcome::Unavailable;
        }
        tracing::info!(
            creator = %correlation.creator,
            bundle_id = %correlation.bundle_id,
            processor = kind.as_str(),
            amount_matched,
            "fiat payment detected (verified by API pull)"
        );
    }
    PullOutcome::Paid { amount_matched }
}

enum Pulled {
    Paid {
        amount_matched: bool,
        /// Processor-side payment reference persisted for reversal lookups:
        /// Stripe payment intent id, PayPal capture id.
        payment_reference: Option<String>,
    },
    Unpaid,
    Unavailable,
}

async fn pull_stripe(stripe: &StripeProcessor, correlation: &Correlation) -> Pulled {
    let Some(session_id) = correlation.session_id.as_deref() else {
        return Pulled::Unpaid;
    };
    let session = match stripe.retrieve_session(session_id).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, session_id, "stripe session pull failed");
            return Pulled::Unavailable;
        }
    };
    if session.payment_status.as_deref() != Some("paid") {
        return Pulled::Unpaid;
    }
    let amount_matched = session.amount_total == Some(correlation.amount_minor)
        && session
            .currency
            .as_deref()
            .is_some_and(|currency| currency.eq_ignore_ascii_case(&correlation.asset));
    Pulled::Paid {
        amount_matched,
        payment_reference: session.payment_intent,
    }
}

async fn pull_paypal(paypal: &PaypalProcessor, correlation: &Correlation) -> Pulled {
    let Some(order_id) = correlation.session_id.as_deref() else {
        return Pulled::Unpaid;
    };
    let order = match paypal.retrieve_order(order_id).await {
        Ok(order) => order,
        Err(error) => {
            tracing::warn!(%error, order_id, "paypal order pull failed");
            return Pulled::Unavailable;
        }
    };
    let order = match order.status.as_deref() {
        Some("COMPLETED") => order,
        // The order carries ORDER_COMPLETE_ON_PAYMENT_APPROVAL, so an order
        // still APPROVED means the auto-capture has not landed: capture
        // explicitly (idempotent per order), then judge the capture result.
        Some("APPROVED") => {
            match paypal
                .capture_order(order_id, &format!("cap-{order_id}"))
                .await
            {
                Ok(captured) => {
                    tracing::info!(order_id, "captured approved paypal order");
                    captured
                }
                Err(error) => {
                    tracing::warn!(%error, order_id, "paypal capture-on-approval failed");
                    return Pulled::Unavailable;
                }
            }
        }
        _ => return Pulled::Unpaid,
    };
    // Order COMPLETED alone is not payment: the capture object's own status
    // must be COMPLETED (design §3.3.3).
    let Some(capture) = order.completed_capture() else {
        return Pulled::Unpaid;
    };
    let amount_matched = capture.amount.as_ref().is_some_and(|amount| {
        amount
            .currency_code
            .eq_ignore_ascii_case(&correlation.asset)
            && decimal_to_minor(&correlation.asset, &amount.value) == Some(correlation.amount_minor)
    });
    Pulled::Paid {
        amount_matched,
        payment_reference: Some(capture.id.clone()),
    }
}

/// Fresh-pull promotion: only called once the settlement delay has elapsed.
/// Reports `true` (promote) only if the pull still says paid + matched.
pub async fn promote_if_still_paid(
    store: &Arc<dyn CorrelationStore>,
    processors: &Processors,
    correlation: &Correlation,
    now: OffsetDateTime,
) -> bool {
    match pull_and_apply(store, processors, correlation, now).await {
        PullOutcome::Paid {
            amount_matched: true,
        } => {
            if let Err(error) = store
                .mark_confirmed(&correlation.creator, &correlation.bundle_id, now)
                .await
            {
                tracing::error!(%error, "failed to persist confirmation");
                return false;
            }
            tracing::info!(
                creator = %correlation.creator,
                bundle_id = %correlation.bundle_id,
                "fiat payment confirmed (settlement delay elapsed, re-pull verified)"
            );
            true
        }
        _ => false,
    }
}
