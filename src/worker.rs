//! Slow-poll fallback: a lost webhook delays a payment but never loses it
//! (design §3.3.3). Every open fiat correlation with a session gets pulled on
//! an interval; the same loop performs delay-elapsed promotion, in which case
//! the pull that just happened IS the fresh promotion-time re-pull.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::store::{CorrelationState, CorrelationStore};
use crate::verification::{pull_and_apply, Processors, PullOutcome};

pub async fn run(
    store: Arc<dyn CorrelationStore>,
    processors: Arc<Processors>,
    poll_interval: Duration,
    settlement_delay: Duration,
) {
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let open = match store.open_fiat_correlations().await {
            Ok(open) => open,
            Err(error) => {
                tracing::error!(%error, "poll worker could not list open correlations");
                continue;
            }
        };
        for correlation in open {
            let now = OffsetDateTime::now_utc();
            let outcome = pull_and_apply(&store, &processors, &correlation, now).await;
            if !matches!(
                outcome,
                PullOutcome::Paid {
                    amount_matched: true
                }
            ) {
                continue;
            }
            // Re-read: pull_and_apply may have just set paid_at.
            let refreshed = match store
                .get(&correlation.creator, &correlation.bundle_id)
                .await
            {
                Ok(Some(refreshed)) => refreshed,
                _ => continue,
            };
            if refreshed.state == CorrelationState::Paid {
                if let Some(paid_at) = refreshed.paid_at {
                    if now >= paid_at + settlement_delay {
                        if let Err(error) = store
                            .mark_confirmed(&refreshed.creator, &refreshed.bundle_id, now)
                            .await
                        {
                            tracing::error!(%error, "poll worker failed to persist confirmation");
                        } else {
                            tracing::info!(
                                creator = %refreshed.creator,
                                bundle_id = %refreshed.bundle_id,
                                "fiat payment confirmed by poll worker (delay elapsed, pull verified)"
                            );
                        }
                    }
                }
            }
        }
    }
}
