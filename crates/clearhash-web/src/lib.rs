//! Reusable Axum router for the ClearHash web frontend.
//!
//! The same `app()` factory powers both the standalone server (`crates/clearhash-web/src/main.rs`)
//! and the Vercel serverless function (`api/clearhash.rs` at the repo root). Anything we add to
//! the surface goes here so both deploy targets stay in sync.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service};
use axum::{Json, Router};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use serde::Deserialize;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub mod templates;

type SiteLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    /// Global rate limit on the inspect endpoint — keeps free-tier deployment bills honest.
    pub inspect_limiter: Arc<SiteLimiter>,
}

impl AppState {
    pub fn new() -> Self {
        // 30 requests / minute, globally. Hard cap so the deployed instance can't be turned into a
        // free npm-attestation proxy.
        let quota = Quota::per_minute(std::num::NonZeroU32::new(30).unwrap());
        AppState {
            inspect_limiter: Arc::new(RateLimiter::direct(quota)),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the Axum router shared by both deploy targets.
///
/// `assets_dir` is the on-disk path to serve at `/assets/*`. The standalone binary passes
/// `"assets"` (working dir is the repo root during dev). The Vercel function ships assets in
/// its bundle; Vercel itself serves anything under `public/` at the CDN edge so the function's
/// nest_service usually never fires there — it's kept as a fallback.
pub fn app(state: AppState, assets_dir: &str) -> Router {
    Router::new()
        .route("/", get(templates::landing))
        .route("/inspect", get(inspect_page))
        .route("/api/inspect", get(api_inspect))
        .route("/healthz", get(healthz))
        .nest_service("/assets", get_service(ServeDir::new(assets_dir)))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(
            #[allow(deprecated)]
            TimeoutLayer::new(Duration::from_secs(20)),
        )
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize, Default)]
struct InspectQuery {
    #[serde(default)]
    package: Option<String>,
}

async fn inspect_page(State(state): State<AppState>, Query(q): Query<InspectQuery>) -> Response {
    match q.package {
        None => templates::inspect_empty().into_response(),
        Some(pkg) => match do_inspect(&state, &pkg).await {
            Ok(result) => templates::inspect_result(&pkg, &result).into_response(),
            Err(err) => templates::inspect_error(&pkg, &err).into_response(),
        },
    }
}

async fn api_inspect(State(state): State<AppState>, Query(q): Query<InspectQuery>) -> Response {
    let Some(pkg) = q.package else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing required query param `package`" })),
        )
            .into_response();
    };
    match do_inspect(&state, &pkg).await {
        Ok(result) => Json(result).into_response(),
        Err(err) => (
            StatusCode::from_u16(err.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(serde_json::json!({ "error": err.message })),
        )
            .into_response(),
    }
}

#[derive(Debug, serde::Serialize)]
pub struct InspectResult {
    pub package: String,
    pub registry_sha256: String,
    pub attestation: Option<InspectAttestation>,
}

#[derive(Debug, serde::Serialize)]
pub struct InspectAttestation {
    pub source_repo: String,
    pub commit_sha: String,
    pub builder_id: String,
    pub issuer_dn: String,
    pub workflow_uri: Option<String>,
    pub rekor_log_index: Option<u64>,
}

#[derive(Debug)]
pub struct InspectError {
    pub status: u16,
    pub message: String,
}

async fn do_inspect(state: &AppState, package: &str) -> Result<InspectResult, InspectError> {
    if state.inspect_limiter.check().is_err() {
        return Err(InspectError {
            status: 429,
            message: "rate limit exceeded (30 req/min global); try again shortly".into(),
        });
    }

    let pkg: clearhash_core::PackageRef =
        package
            .parse()
            .map_err(|e: clearhash_core::Error| InspectError {
                status: 400,
                message: format!("invalid package reference: {e}"),
            })?;

    let adapter = clearhash_ecosystems::for_ecosystem(pkg.ecosystem);
    let fetched = clearhash_registry::fetch(&*adapter, &pkg)
        .await
        .map_err(|e| InspectError {
            status: 502,
            message: format!("upstream registry fetch failed: {e}"),
        })?;

    let attestation = match fetched.attestation_bundle.as_ref() {
        Some(bytes) => match clearhash_provenance::verify(&*adapter, bytes).await {
            Ok(v) => Some(InspectAttestation {
                source_repo: v.claim.source_repo,
                commit_sha: v.claim.commit_sha,
                builder_id: v.claim.builder_id,
                issuer_dn: v.identity.issuer_dn,
                workflow_uri: v.identity.workflow_uri,
                rekor_log_index: v.identity.rekor_log_index,
            }),
            Err(e) => {
                return Err(InspectError {
                    status: 422,
                    message: format!("attestation present but failed verification: {e}"),
                });
            }
        },
        None => None,
    };

    Ok(InspectResult {
        package: pkg.to_string(),
        registry_sha256: clearhash_core::hex_digest(&fetched.registry_sha256),
        attestation,
    })
}
