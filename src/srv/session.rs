use chrono::{DateTime, Utc};

use crate::{
    api::{
        error::{ApiError, ApiResult, VerifyStatusApiExt},
        session::{SessionRequest, SessionResponsePayload}, SignedMessage,
    },
    config::SrvConfig,
    model::Model,
};

pub async fn start_session(
    now: DateTime<Utc>,
    cfg: &SrvConfig,
    model: &Model,
    req: SessionRequest,
) -> ApiResult<Vec<u8>> {
    let identity = req.payload().identity.clone();
    model.check_identity(now, &req.payload().identity).await?;
    req.verify(&identity).to_api_result()?;
    let (srv_ident, srv_cert) = model.fetch_server_identity_for(now, &identity).await?;

    let (session_id, enc_key) = model
        .register_session(
            now,
            cfg.max_session_duration,
            &identity,
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
