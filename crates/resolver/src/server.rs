//! HTTP boundary for the resolver service.
//!
//! The router is kept in the library so tests can exercise the real body,
//! JSON, and response mapping rules without starting a process.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use web_bot_auth_protocol::ResolveRequest;

use crate::{FetchErrorKind, ResolverService};

#[derive(Clone)]
struct AppState {
    resolver: ResolverService,
}

pub fn router(resolver: ResolverService) -> Router {
    Router::new()
        .route("/v1/resolve", post(resolve))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(resolver.inbound_body_limit()))
        .with_state(AppState { resolver })
}

async fn resolve(
    State(state): State<AppState>,
    Json(request): Json<ResolveRequest>,
) -> impl IntoResponse {
    match state.resolver.resolve(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) if error.kind == FetchErrorKind::BadRequest => {
            (StatusCode::BAD_REQUEST, "invalid resolver request\n").into_response()
        }
        Err(error) => {
            eprintln!(
                "resolver event=resolution_failure reason={}",
                error.kind.as_str()
            );
            (StatusCode::SERVICE_UNAVAILABLE, "resolution unavailable\n").into_response()
        }
    }
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}
