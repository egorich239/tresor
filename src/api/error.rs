use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum TransportError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request")]
    BadRequest,

    #[error("internal error")]
    Internal,
}

impl TransportError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            TransportError::BadRequest => StatusCode::BAD_REQUEST,
            TransportError::Forbidden => StatusCode::FORBIDDEN,
            TransportError::Unauthorized => StatusCode::UNAUTHORIZED,
            TransportError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for TransportError {
    fn into_response(self) -> Response {
        self.status_code().into_response()
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum AppError {
    #[error("internal error: {0}")]
    Internal(String),
}

pub type AppResult<T> = std::result::Result<T, AppError>;

pub type TransportResult<T> = std::result::Result<T, TransportError>;
