use crate::{
    age::RecepientStr,
    api::error::{ApiResult, VerifyStatusApiExt},
    config::SrvConfig,
    identity::{Certificate, SignedMessage, VerifyingKeyHex},
    model::{Model, SessionEncKey},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type SessionRequest = SignedMessage<SessionRequestPayload>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionRequestPayload {
    pub nonce: String,
    pub identity: VerifyingKeyHex,
    pub recepient: RecepientStr,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionResponsePayload {
    pub nonce: String,
    pub session_id: String,
    pub certificate: Certificate,
    pub enc_key: SessionEncKey,
}

pub type SessionResponse = SignedMessage<SessionResponsePayload>;

pub async fn start_session(
    now: DateTime<Utc>,
    cfg: &SrvConfig,
    model: &Model,
    req: SessionRequest,
) -> ApiResult<Vec<u8>> {
    let cli_ident = model.fetch_identity(now, &req.payload().identity).await?;
    req.verify(&cli_ident).as_api_result()?;
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

    let response = SignedMessage::sign(response_payload, &srv_ident);
    Ok(req.payload().recepient.encrypt(response))
}
