use crate::{
    api::{ApiResult, SecretRequest, SecretResponse},
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};
use axum::{extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};

pub async fn secret_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<SecretRequest, 'a'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session.respond_api(_secret_handler(&app, &session, query, now).await)
}

async fn _secret_handler(
    app: &AppState,
    session: &SessionState,
    query: SecretRequest,
    now: DateTime<Utc>,
) -> ApiResult<SecretResponse> {
    let mut tx = app.model().tx(now).await?;
    let session_id = tx.get_session(session.session_id()).await?;
    let res = match query {
        SecretRequest::Add {
            name,
            value,
            description,
        } => {
            tx.secret_add(&session_id, &name, &value, &description)
                .await
        }
        SecretRequest::Update { name, value } => tx.secret_update(&session_id, &name, &value).await,
        SecretRequest::Delete { name } => tx.secret_delete(&session_id, &name).await,
    }?;
    tx.commit().await?;
    Ok(res)
}
