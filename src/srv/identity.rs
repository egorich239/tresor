use axum::{extract::State, response::IntoResponse};

use crate::{
    api::{ApiResult, IdentityRequest, IdentityResponse},
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};

pub async fn identity_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<IdentityRequest, 'a'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session
        .response(_identity_handler(&app, &session, query, now).await)
        .await
}

async fn _identity_handler(
    app: &AppState,
    session: &SessionState,
    req: IdentityRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> ApiResult<IdentityResponse> {
    let mut tx = app.model().tx(now).await?;
    let session_id = tx.get_session(session.session_id()).await?;
    let res = match req {
        IdentityRequest::Add { name, key, role } => {
            tx.identity_add(&session_id, &name, &key, role).await?
        }
    };
    tx.commit().await?;
    Ok(res)
}
