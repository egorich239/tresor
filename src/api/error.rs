use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::VerifyStatus;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ApiError {
    #[error("invalid request syntax")]
    BadRequest,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unauthorized")]
    Unauthorized,

    #[error("invalid identity")]
    InvalidIdentity,

    #[error("invalid server identity")]
    InvalidServerIdentity,

    #[error("transient error, retry later")]
    TransientError,

    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::InvalidSignature => StatusCode::FORBIDDEN,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::InvalidIdentity => StatusCode::FORBIDDEN,
            ApiError::InvalidServerIdentity => StatusCode::FORBIDDEN,
            ApiError::TransientError => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn sanitize(&mut self) {}
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.status_code();
        let body = serde_json::to_string(&self).unwrap_or_else(|_| "Internal server error".to_string());
        (status_code, body).into_response()
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
pub trait VerifyStatusApiExt {
    fn to_api_result(self) -> ApiResult<()>;
}

impl VerifyStatusApiExt for VerifyStatus {
    fn to_api_result(self) -> ApiResult<()> {
        match self {
            VerifyStatus::Ok => Ok(()),
            VerifyStatus::Failed => Err(ApiError::InvalidSignature),
        }
    }
}
