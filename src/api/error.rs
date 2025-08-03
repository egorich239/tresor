use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::identity::VerifyStatus;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid identity")]
    InvalidIdentity,

    #[error("invalid server identity")]
    InvalidServerIdentity,

    #[error("transient error, retry later")]
    TransientError,

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ApiError> for Response {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::InvalidSignature => {
                (StatusCode::FORBIDDEN, "invalid signature").into_response()
            }
            ApiError::InvalidIdentity => {
                (StatusCode::FORBIDDEN, "invalid identity").into_response()
            }
            ApiError::InvalidServerIdentity => {
                (StatusCode::FORBIDDEN, "no matching server identity found").into_response()
            }
            ApiError::TransientError => {
                (StatusCode::SERVICE_UNAVAILABLE, "transient error, retry later").into_response()
            }
            ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
pub trait VerifyStatusApiExt {
    fn as_api_result(self) -> ApiResult<()>;
}

impl VerifyStatusApiExt for VerifyStatus {
    fn as_api_result(self) -> ApiResult<()> {
        match self {
            VerifyStatus::Ok => Ok(()),
            VerifyStatus::Failed => Err(ApiError::InvalidSignature),
        }
    }
}
