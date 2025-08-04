use thiserror::Error;

use crate::{api::error::ApiError, identity::SignatureError};

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
}

pub type ClientResult<T> = Result<T, ClientError>;
