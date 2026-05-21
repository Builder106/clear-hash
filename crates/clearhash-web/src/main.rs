//! Standalone HTTP server. Re-uses the Axum router defined in `clearhash_web::app`.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("clearhash_web=info,tower_http=info")
            }),
        )
        .compact()
        .init();

    let state = clearhash_web::AppState::new();
    let app = clearhash_web::app(state, "assets");

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("clearhash-web listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
