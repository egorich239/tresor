use crate::{
    api::{
        error::{ApiError, ApiResult},
        secret::SecretRequest,
    },
    enc,
    model::Model,
    srv::session::XTresorSessionId,
};
use aes_gcm::Nonce;
use axum::{body::Bytes, extract::State, response::IntoResponse};

pub async fn secret_handler(
    State(model): State<Model>,
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

    let payload =
        enc::decrypt(ciphertext, nonce, &enc_key).ok_or(ApiError::BadRequest)?;

    let request: SecretRequest =
        serde_json::from_slice(&payload).map_err(|_| ApiError::BadRequest)?;

    match request {
        SecretRequest::Add {
            name,
            value,
            description,
        } => model.secret_add(&name, &value, &description).await?,
        SecretRequest::Update { name, value } => model.secret_update(&name, &value).await?,
        SecretRequest::Delete { name } => model.secret_delete(&name).await?,
    };

    let response = serde_json::to_vec(&()).map_err(ApiError::internal)?;
    let (response, _nonce) = enc::encrypt(&response, &enc_key).map_err(ApiError::internal)?;

    Ok(response)
}
