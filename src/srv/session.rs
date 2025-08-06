use axum::{
    Json,
    body::Body,
    extract::{FromRequest, FromRequestParts, Request},
    http::request::Parts,
};
use chrono::{DateTime, Utc};

use crate::{
    api::{
        SignedMessage,
        error::{ApiError, ApiResult, VerifyStatusApiExt},
        session::{SessionId, SessionRequest, SessionResponsePayload},
    },
    config::SrvConfig,
    model::Model,
};

pub async fn start_session(
    now: DateTime<Utc>,
    cfg: &SrvConfig,
    model: &Model,
    req: Request<Body>,
) -> ApiResult<Vec<u8>> {
    let Json(req): Json<SessionRequest> = Json::from_request(req, &())
        .await
        .map_err(|_| ApiError::BadRequest)?;
    let identity = req.payload().identity.clone();
    model.check_identity(now, &req.payload().identity).await?;
    req.verify(&identity).to_api_result()?;
    let (srv_ident, srv_cert) = model.fetch_server_identity_for(now, &identity).await?;

    let (session_id, enc_key) = model
        .register_session(
            now,
            cfg.max_session_duration,
            req.payload().nonce.clone(),
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
    let bytes = serde_json::to_vec(&response)
        .map_err(|e| ApiError::Internal(format!("failed to serialize: {e}")))?;
    Ok(req.payload().recepient.encrypt(&bytes))
}

// Custom header type for `X-Tresor-Session-Id`
pub struct XTresorSessionId(pub SessionId);

impl<S> FromRequestParts<S> for XTresorSessionId
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let session_id = parts
            .headers
            .get("X-Tresor-Session-Id")
            .ok_or(ApiError::Unauthorized)?;
        let session_id = session_id.to_str().map_err(|_| ApiError::Unauthorized)?;
        let session_id = session_id.try_into().map_err(|_| ApiError::Unauthorized)?;
        Ok(XTresorSessionId(session_id))
    }
}
