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
use aes_gcm::Nonce;
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
    let (nonce, ciphertext) = body.split_at(12);
    let nonce = Nonce::from_slice(nonce);
    // TODO: verify that nonce has not been used before during this session.

    let payload = enc::decrypt(ciphertext, nonce, &enc_key).ok_or(ApiError::BadRequest)?;

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
                .secret_add(&session_id, &name, &value, &description)
                .await?
        }
        SecretRequest::Update { name, value } => {
            model.secret_update(&session_id, &name, &value).await?
        }
        SecretRequest::Delete { name } => model.secret_delete(&session_id, &name).await?,
    };

    let response_payload =
        serde_json::to_vec(&SecretResponse::Success).map_err(ApiError::internal)?;
    let (response_payload, nonce) =
        enc::encrypt(&response_payload, &enc_key).map_err(ApiError::internal)?;

    let mut response = Vec::new();
    response.extend_from_slice(&nonce);
    response.extend_from_slice(&response_payload);

    Ok(response)
}
