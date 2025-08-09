use axum::{extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};

use crate::{
    api::{
        ServerIdentityClaim,
        claim::{ClaimRequest, ClaimResponse},
        error::ApiResult,
    },
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};

pub async fn claim_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<ClaimRequest, 'a'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session
        .response(_claim_handler(&app, query, now).await)
        .await
}

pub async fn _claim_handler(
    app: &AppState,
    req: ClaimRequest,
    now: DateTime<Utc>,
) -> ApiResult<ClaimResponse> {
    let mut tx = app.model().tx(now).await?;
    let claim = tx.get_server_identity_claim(&req.issuer).await?;
    Ok(ClaimResponse { claim })
}
