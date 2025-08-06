//! `tresor secret` subcommand implementation.

use crate::api::secret::{SecretRequest, SecretResponse};
use crate::cli::error::ClientResult;
use crate::cli::session::Session;

pub fn secret_add(
    session: &Session,
    name: String,
    value: String,
    description: String,
) -> ClientResult<SecretResponse> {
    session.query(SecretRequest::Add {
        name,
        value,
        description,
    })
}

pub fn secret_update(
    session: &Session,
    name: String,
    value: String,
) -> ClientResult<SecretResponse> {
    session.query(SecretRequest::Update { name, value })
}

pub fn secret_delete(
    session: &Session,
    name: String,
) -> ClientResult<SecretResponse> {
    session.query(SecretRequest::Delete { name })
}
