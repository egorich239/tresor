use chrono::{DateTime, Utc};

use crate::{
    api::{
        error::{ApiError, ApiResult, VerifyStatusApiExt},
        session::{SessionRequest, SessionResponsePayload},
    },
    config::SrvConfig,
    identity::SignedMessage,
    model::Model,
};

pub async fn start_session(
    now: DateTime<Utc>,
    cfg: &SrvConfig,
    model: &Model,
    req: SessionRequest,
) -> ApiResult<Vec<u8>> {
    let cli_ident = model.fetch_identity(now, &req.payload().identity).await?;
    req.verify(&cli_ident).to_api_result()?;
    let (srv_ident, srv_cert) = model.fetch_server_identity_for(now, &cli_ident).await?;

    let (session_id, enc_key) = model
        .register_session(
            now,
            cfg.max_session_duration,
            &cli_ident,
            &srv_ident.verifying_identity(),
        )
        .await?;

    let response_payload = SessionResponsePayload {
        nonce: req.payload().nonce.clone(),
        session_id,
        certificate: srv_cert,
        enc_key,
    };

    let response = SignedMessage::new(response_payload, &srv_ident)
        .map_err(|_| ApiError::Internal("failed to sign response".to_string()))?;
    Ok(req.payload().recepient.encrypt(response))
}
