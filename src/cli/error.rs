use std::io;

use thiserror::Error;

use crate::{api::error::ApiError, config::ConfigError, identity::SignatureError};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ApiError(#[from] ApiError),

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error("malformed response")]
    MalformedResponse,

    #[error("invalid server signature")]
    InvalidServerSignature,

    #[error("root config error")]
    RootConfigError(#[from] ConfigError),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

pub type ClientResult<T> = Result<T, ClientError>;
