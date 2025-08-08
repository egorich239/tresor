use crate::{
    api::secret::SecretRequest,
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery},
    },
};
use axum::{extract::State, response::IntoResponse};

pub async fn secret_handler(
    State(app): State<AppState>,
    CurrentTime(_): CurrentTime,
    SessionQuery { session, query, .. }: SessionQuery<SecretRequest, 'a'>,
) -> impl IntoResponse {
    let model = app.model();
    let session = session.read().await;
    let session_id = session.session_id();
    let res = match query {
        SecretRequest::Add {
            name,
            value,
            description,
        } => {
            model
                .secret_add(session_id, &name, &value, &description)
                .await
        }
        SecretRequest::Update { name, value } => {
            model.secret_update(session_id, &name, &value).await
        }
        SecretRequest::Delete { name } => model.secret_delete(session_id, &name).await,
    };
    session.response(res).await
}
