
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::VerifyStatus;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request")]
    BadRequest,

    #[error("internal error")]
    Internal,
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.status_code().into_response()
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
            VerifyStatus::Failed => Err(ApiError::Forbidden),
        }
    }
}
