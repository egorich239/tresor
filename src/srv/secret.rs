use crate::{
    api::{
        error::{ApiError, ApiResult},
        secret::{SecretRequest, SecretResponse},
    },
    config::SrvConfig,
    enc,
    model::Model,
    srv::session::XTresorSessionId,
};
use axum::{body::Bytes, extract::State, response::IntoResponse};

pub async fn secret_handler(
    State((_config, model)): State<(SrvConfig, Model)>,
    XTresorSessionId(session_id): XTresorSessionId,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    // TODO: check that this is admin session.
    let enc_key = model
        .get_session_key(&session_id)
        .await
        .ok_or(ApiError::Unauthorized)?;
    let aes_session = enc::AesSession::new(enc_key, session_id);
    let session_id = aes_session.session_id();
    // TODO: verify that nonce has not been used before during this session.

    let payload = aes_session
        .decrypt(body.as_ref().try_into().map_err(|_| ApiError::BadRequest)?)
        .ok_or(ApiError::BadRequest)?;

    let request: SecretRequest =
        serde_json::from_slice(&payload).map_err(|_| ApiError::BadRequest)?;

    // TODO: errors must also be encrypted!
    match request {
        SecretRequest::Add {
            name,
            value,
            description,
        } => {
            model
                .secret_add(session_id, &name, &value, &description)
                .await?
        }
        SecretRequest::Update { name, value } => {
            model.secret_update(session_id, &name, &value).await?
        }
        SecretRequest::Delete { name } => model.secret_delete(session_id, &name).await?,
    };

    let response = serde_json::to_vec(&SecretResponse::Success).map_err(ApiError::internal)?;
    let response: Vec<_> = aes_session.encrypt(&response).into();
    Ok(response)
}
