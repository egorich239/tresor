use std::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::VerifyStatus;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ApiError {
    #[error("invalid request syntax")]
    BadRequest,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid identity")]
    InvalidIdentity,

    #[error("invalid server identity")]
    InvalidServerIdentity,

    #[error("invalid certificate")]
    InvalidCertificate,

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::InvalidSignature => StatusCode::FORBIDDEN,
            ApiError::InvalidIdentity => StatusCode::FORBIDDEN,
            ApiError::InvalidServerIdentity => StatusCode::FORBIDDEN,
            ApiError::InvalidCertificate => StatusCode::FORBIDDEN,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn sanitize(&mut self) {}

    pub fn internal(e: impl fmt::Display) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(mut self) -> Response {
        self.sanitize();
        (self.status_code(), Json(self)).into_response()
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
