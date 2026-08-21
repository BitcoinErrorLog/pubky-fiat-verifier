//! The pull-is-truth core: every state advance flows through a fresh read of
//! the processor's API. Webhooks and the slow poll both funnel into
//! `pull_and_apply`; the promotion to `confirmed` additionally requires the
//! settlement delay to have elapsed AND a fresh pull at promotion time.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::store::{Correlation, CorrelationState, CorrelationStore};
use crate::stripe::StripeProcessor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullOutcome {
    /// Session shows `payment_status == "paid"`; carries the amount check.
    Paid {
        amount_matched: bool,
    },
    Unpaid,
    /// Transport or processor error: state must not move.
    Unavailable,
}

/// Pulls the correlation's checkout session from Stripe and applies the
/// verified fact to the store. Returns what the pull established.
pub async fn pull_and_apply(
    store: &Arc<dyn CorrelationStore>,
    stripe: &StripeProcessor,
    correlation: &Correlation,
    now: OffsetDateTime,
) -> PullOutcome {
    let Some(session_id) = correlation.session_id.as_deref() else {
        return PullOutcome::Unpaid;
    };
    let session = match stripe.retrieve_session(session_id).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, session_id, "stripe session pull failed");
            return PullOutcome::Unavailable;
        }
    };
    if session.payment_status.as_deref() != Some("paid") {
        return PullOutcome::Unpaid;
    }
    let amount_matched = session.amount_total == Some(correlation.amount_minor)
        && session
            .currency
            .as_deref()
            .is_some_and(|currency| currency.eq_ignore_ascii_case(&correlation.asset));
    if !amount_matched {
        tracing::error!(
            session_id,
            expected_amount = correlation.amount_minor,
            expected_asset = %correlation.asset,
            pulled_amount = ?session.amount_total,
            pulled_currency = ?session.currency,
            "paid checkout session does not match the lock criterion"
        );
    }
    if correlation.state == CorrelationState::Created {
        if let Err(error) = store
            .mark_paid(
                &correlation.creator,
                &correlation.bundle_id,
                amount_matched,
                session.payment_intent.as_deref(),
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
            amount_matched,
            "fiat payment detected (verified by API pull)"
        );
    }
    PullOutcome::Paid { amount_matched }
}

/// Fresh-pull promotion: only called once the settlement delay has elapsed.
/// Reports `true` (promote) only if the pull still says paid + matched.
pub async fn promote_if_still_paid(
    store: &Arc<dyn CorrelationStore>,
    stripe: &StripeProcessor,
    correlation: &Correlation,
    now: OffsetDateTime,
) -> bool {
    match pull_and_apply(store, stripe, correlation, now).await {
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
