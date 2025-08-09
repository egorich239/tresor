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

impl From<StatusCode> for TransportError {
    fn from(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => TransportError::BadRequest,
            StatusCode::FORBIDDEN => TransportError::Forbidden,
            StatusCode::UNAUTHORIZED => TransportError::Unauthorized,
            StatusCode::INTERNAL_SERVER_ERROR => TransportError::Internal,
            _ => TransportError::Internal,
        }
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum AppError {
    #[error("secret already exists")]
    SecretAlreadyExists,

    #[error("secret not found")]
    SecretNotFound,

    #[error("identity already exists")]
    IdentityAlreadyExists,

    #[error("identity not found")]
    IdentityNotFound,

    #[error("env already exists")]
    EnvAlreadyExists,

    #[error("unknown key: {0}")]
    UnknownKey(String),
}

pub type AppResult<T> = std::result::Result<T, AppError>;

pub type TransportResult<T> = std::result::Result<T, TransportError>;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    App(#[from] AppError),
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
