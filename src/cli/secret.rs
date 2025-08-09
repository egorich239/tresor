//! `tresor secret` subcommand implementation.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::{
    api::{SecretRequest, SecretResponse},
    cli::{error::ClientResult, session::Session},
};

#[derive(Debug, Deserialize)]
struct SecretOps {
    #[serde(default)]
    op: Vec<SecretRequest>,
}

pub fn secret_edit(session: &Session, script: PathBuf) -> ClientResult<()> {
    let requests = fs::read_to_string(script)?;
    let ops: SecretOps = toml::from_str(&requests)?;

    for op in ops.op {
        let name = op.name().to_string();
        let resp: ClientResult<SecretResponse> = session.query("secret", op);
        match resp {
            Err(e) => println!("{name}\terror: {e}"),
            Ok(SecretResponse::Success) => println!("{name}\tsuccess"),
            Ok(SecretResponse::KeyExists) => println!("{name}\texists"),
            Ok(SecretResponse::KeyNotFound) => println!("{name}\tnot found"),
        }
    }

    Ok(())
}
