//! Vercel serverless function. Wraps the shared Axum router (`clearhash_web::app`) with
//! `vercel_runtime::axum::VercelLayer` so a single function handles every route.
//!
//! Routing model:
//!   - `vercel.json` rewrites `/(.*)` → `/api/clearhash` so this function receives every URL.
//!   - The router's own internal routing dispatches `/`, `/inspect`, `/api/inspect`, `/healthz`,
//!     and `/assets/*` (the last is served by Vercel's CDN from `public/assets/` when the file
//!     exists; the function's ServeDir fallback only fires if it doesn't).

use tower::ServiceBuilder;
use vercel_runtime::axum::VercelLayer;
use vercel_runtime::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Lambda's filesystem layout differs from the local dev tree. The function bundle copies
    // `assets/` into `/var/task/assets/` at deploy time (see `.vercelignore` allowlist), so the
    // relative path works either way.
    let state = clearhash_web::AppState::new();
    let router = clearhash_web::app(state, "assets");

    let app = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(router);

    vercel_runtime::run(app).await
}
