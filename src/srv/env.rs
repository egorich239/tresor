use axum::{extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};

use crate::{
    api::{ApiResult, EnvRequest, EnvResponse},
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};

pub async fn env_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<EnvRequest, 'a'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session
        .response(_env_handler(&app, &session, query, now).await)
        .await
}

async fn _env_handler(
    app: &AppState,
    session: &SessionState,
    query: EnvRequest,
    now: DateTime<Utc>,
) -> ApiResult<EnvResponse> {
    let mut tx = app.model().tx(now).await?;
    let session_id = tx.get_session(session.session_id()).await?;

    let res = match query {
        EnvRequest::Create { env, pairs } => tx.env_create(&session_id, &env, &pairs).await?,
    };

    tx.commit().await?;
    Ok(res)
}
