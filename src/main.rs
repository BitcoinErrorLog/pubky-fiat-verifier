mod auth;
mod config;
mod error;
mod http;
#[cfg(test)]
mod http_tests;
mod lock_fetch;
mod proxy;
mod rate_limit;
mod state;
mod store;
mod stripe;
mod verification;
mod wire;
mod worker;

use std::sync::Arc;

use crate::config::Config;
use crate::http::AppState;
use crate::lock_fetch::PubkyCriterionSource;
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::store::{CorrelationStore, PostgresStore};
use crate::stripe::StripeProcessor;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            std::process::exit(1);
        }
    };

    let store: Arc<dyn CorrelationStore> = match PostgresStore::connect(&config.database_url).await
    {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("database error: {error}");
            std::process::exit(1);
        }
    };

    let stripe = config.stripe.as_ref().map(|stripe_config| {
        Arc::new(StripeProcessor::new(
            stripe_config.api_base.clone(),
            stripe_config.secret_key.clone(),
            stripe_config.webhook_secret.clone(),
        ))
    });

    if let Some(stripe) = stripe.as_ref() {
        tokio::spawn(worker::run(
            store.clone(),
            stripe.clone(),
            config.poll_interval,
            config.settlement_delay,
        ));
    }

    let state = Arc::new(AppState {
        trusted_key: config.trusted_locks_public_key,
        store,
        stripe: stripe.clone(),
        criterion_source: Arc::new(
            match PubkyCriterionSource::new(
                config.lock_resource_max_bytes,
                config.lock_fetch_timeout,
            ) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("pubky client error: {error}");
                    std::process::exit(1);
                }
            },
        ),
        proxy: Arc::new(PaykitProxy::new(config.paykit_server_url.clone())),
        settlement_delay: config.settlement_delay,
        synthesized_confirmations: config.synthesized_confirmations,
        allowed_assets: config.allowed_assets.clone(),
        checkout_success_url: config.checkout_success_url.clone(),
        checkout_cancel_url: config.checkout_cancel_url.clone(),
        checkout_limiter: TokenBucket::new(
            config.checkout_rate_per_second,
            config.checkout_rate_burst,
        ),
    });

    tracing::info!(
        bind_addr = %config.bind_addr,
        paykit_server_url = %config.paykit_server_url,
        stripe_enabled = stripe.is_some(),
        settlement_delay_seconds = config.settlement_delay.as_secs(),
        synthesized_confirmations = config.synthesized_confirmations,
        allowed_assets = ?config.allowed_assets,
        "starting pubky-fiat-verifier"
    );

    let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind {}: {error}", config.bind_addr);
            std::process::exit(1);
        }
    };

    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("http server run");
}
