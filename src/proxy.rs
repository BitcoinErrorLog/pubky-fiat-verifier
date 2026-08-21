//! Transparent BTC pass-through to the real Paykit Server. The original raw
//! body and `X-Paykit-Signature` header are forwarded verbatim: the signature
//! covers only the canonical body, and the Paykit Server keeps trusting the
//! Lock Server key, so the gateway needs no key of its own on this path.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use url::Url;

use crate::auth::SIGNATURE_HEADER;
use crate::error::ApiError;

pub struct PaykitProxy {
    http: reqwest::Client,
    server_url: Url,
}

impl PaykitProxy {
    pub fn new(server_url: Url) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build()
                .expect("static reqwest client configuration"),
            server_url,
        }
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut endpoint = self.server_url.clone();
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        {
            let mut segments = endpoint
                .path_segments_mut()
                .expect("validated http(s) server_url supports path segments");
            segments.pop_if_empty();
            for segment in path.split('/') {
                segments.push(segment);
            }
        }
        endpoint
    }

    /// Forwards the signed call and mirrors the upstream status + body, so
    /// the Lock Server observes exactly what the Paykit Server answered.
    pub async fn forward(&self, path: &str, signature: &str, raw_body: Bytes) -> Response {
        let upstream = self
            .http
            .post(self.endpoint(path))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature)
            .body(raw_body)
            .send()
            .await;
        match upstream {
            Ok(response) => {
                let status = StatusCode::from_u16(response.status().as_u16())
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("application/json")
                    .to_owned();
                match response.bytes().await {
                    Ok(body) => (
                        status,
                        [(axum::http::header::CONTENT_TYPE, content_type)],
                        body,
                    )
                        .into_response(),
                    Err(error) => {
                        tracing::error!(%error, path, "paykit proxy body read failed");
                        ApiError::Unavailable.into_response()
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, path, "paykit proxy request failed");
                ApiError::Unavailable.into_response()
            }
        }
    }
}
