use axum::{extract::State, response::Response};
use chrono::{DateTime, Utc};

use crate::{
    api::{ApiResult, ClaimRequest, ClaimResponse},
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery},
    },
};

pub async fn claim_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<ClaimRequest, 'a'>,
) -> Response {
    session
        .read()
        .await
        .respond_api(_claim_handler(&app, query, now).await)
}

pub async fn _claim_handler(
    app: &AppState,
    req: ClaimRequest,
    now: DateTime<Utc>,
) -> ApiResult<ClaimResponse> {
    let mut tx = app.model().tx(now).await?;
    let claim = tx.get_server_identity_claim(&req.issuer).await?;
    tx.commit().await?;
    Ok(ClaimResponse { claim })
}
